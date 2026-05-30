/**
 * AUNClient — AUN Core SDK 主客户端
 *
 * 完整实现，与 Python SDK client.py 对齐。
 * 功能：
 * - 连接/断线重连/关闭
 * - RPC 调用（含 E2EE 自动加解密编排）
 * - 事件自动解密管线（P2P + 群组）
 * - 后台任务（心跳、token 刷新、V2 bootstrap 缓存清理）
 * - 客户端签名（关键操作）
 * - 群组 E2EE 全自动编排（建群/加人/踢人/退出）
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as https from 'node:https';
import * as path from 'node:path';
import { URL } from 'node:url';

import { configFromMap, getDeviceId, normalizeInstanceId, type AUNConfig } from './config.js';
import { CryptoProvider } from './crypto.js';
import { GatewayDiscovery } from './discovery.js';
import { DnsResilientNet } from './net.js';
import type { ProtectedHeadersInput } from './protected-headers.js';
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
import { EventDispatcher, type EventPayload, type Subscription, type EventHandler } from './events.js';
import { FileKeyStore } from './keystore/file.js';
import type { KeyStore } from './keystore/index.js';
import { AUNLogger, type ModuleLogger } from './logger.js';
import { normalizeGroupId } from './group-id.js';

import { RPCTransport } from './transport.js';
import { AuthFlow } from './auth.js';
import { SeqTracker } from './seq-tracker.js';
import { V2Session, V2KeyStore, type CallFn } from './v2/session/index.js';
import {
  encryptP2PMessage, encryptGroupMessage, decryptMessage,
  type Target, type StateCommitmentAAD,
} from './v2/e2ee/index.js';
import { ecdsaVerifyRaw } from './v2/crypto/ecdsa.js';
import { computeStateCommitment } from './v2/state/index.js';
import {
  isJsonObject,
  type IdentityRecord,
  type JsonObject,
  type JsonValue,
  type Message,
  type MetadataRecord,
  type RpcParams,
  type RpcResult,
  ConnectionState,
  STATE_TO_PUBLIC,
} from './types.js';
import { AID } from './aid.js';

type AgentMdFetchResult = {
  aid: string;
  content: string;
  signature: Record<string, unknown>;
  in_sync: boolean | null;
  saved_to: string | null;
  save_error: string | null;
};

function isPromiseLike<T = unknown>(value: unknown): value is PromiseLike<T> {
  return Boolean(value && typeof (value as { then?: unknown }).then === 'function');
}


/**
 * 递归排序键的 JSON 序列化（Canonical JSON for AUN）
 * 等价于 Python json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)
 * 非 ASCII 字符直接以 UTF-8 输出，与 AAD 序列化规则一致。
 */
export function stableStringify(obj: JsonValue | object | undefined): string {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj === 'boolean' || typeof obj === 'number') return JSON.stringify(obj);
  if (typeof obj === 'string') return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return '[' + obj.map(v => stableStringify(v)).join(',') + ']';
  }
  if (isJsonObject(obj)) {
    const keys = Object.keys(obj).sort();
    // 跳过值为 undefined 的 key，与 JSON.stringify 行为一致（ISSUE-TS-001）
    const entries = keys
      .filter(k => obj[k] !== undefined)
      .map(k => stableStringify(k) + ':' + stableStringify(obj[k]));
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

function computeStateHash(params: {
  groupId: string;
  stateVersion: number;
  keyEpoch: number;
  members: Array<{ aid: string; role: string }>;
  policy: Record<string, unknown>;
  prevStateHash: string;
}): string {
  const sortedMembers = [...params.members].sort((a, b) => a.aid.localeCompare(b.aid));
  const membershipBlock = sortedMembers.map(m => `${m.aid}:${m.role}`).join('|');
  const sortedPolicy: Record<string, unknown> = {};
  for (const key of Object.keys(params.policy).sort()) {
    sortedPolicy[key] = params.policy[key];
  }
  const policyBlock = Object.keys(params.policy).length > 0 ? JSON.stringify(sortedPolicy) : '';
  const prevBytes = params.prevStateHash ? Buffer.from(params.prevStateHash, 'hex') : Buffer.alloc(32);
  const svBuf = Buffer.alloc(8);
  svBuf.writeBigUInt64BE(BigInt(params.stateVersion));
  const keBuf = Buffer.alloc(8);
  keBuf.writeBigUInt64BE(BigInt(params.keyEpoch));
  const data = Buffer.concat([
    Buffer.from(params.groupId, 'utf-8'), Buffer.from([0x00]),
    svBuf, Buffer.from([0x00]),
    keBuf, Buffer.from([0x00]),
    Buffer.from(membershipBlock, 'utf-8'), Buffer.from([0x00]),
    Buffer.from(policyBlock, 'utf-8'), Buffer.from([0x00]),
    prevBytes,
  ]);
  return crypto.createHash('sha256').update(data).digest('hex');
}

// ── 常量 ──────────────────────────────────────────────────────

/** 内部专用方法，禁止外部直接调用 */
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
  'group.e2ee.begin_rotation',
  'group.e2ee.commit_rotation',
  'group.e2ee.abort_rotation',
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
}

export interface ConnectionOptions {
  auto_reconnect?: boolean;
  connect_timeout?: number;
  retry_initial_delay?: number;
  retry_max_delay?: number;
  retry_max_attempts?: number;
  heartbeat_interval?: number;
  call_timeout?: number;
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

export interface AUNClientOptions extends Record<string, unknown> {
  root_ca_path?: string;
  rootCaPath?: string;
  verify_ssl?: boolean;
  verifySSL?: boolean;
  verifySsl?: boolean;
  require_forward_secrecy?: boolean;
  requireForwardSecrecy?: boolean;
  replay_window_seconds?: number;
  replayWindowSeconds?: number;
  debug?: boolean;
  protected_headers?: Record<string, unknown> | null;
  aid?: never;
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

const PROTECTED_HEADERS_METHODS = new Set([
  'message.send',
  'group.send',
  'message.thought.put',
  'group.thought.put',
]);

const RECONNECT_MIN_BASE_DELAY_MS = 1_000;
const RECONNECT_MAX_BASE_DELAY_MS = 64_000;
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
const NON_IDEMPOTENT_TIMEOUT_MS = 35_000;
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

function clampReconnectDelayMs(
  value: unknown,
  fallback: number,
  upper = RECONNECT_MAX_BASE_DELAY_MS,
): number {
  const parsed = Number(value);
  const ms = Number.isFinite(parsed) ? parsed : fallback;
  return Math.min(Math.max(ms, RECONNECT_MIN_BASE_DELAY_MS), upper);
}

function reconnectSleepDelayMs(baseDelay: number, maxBaseDelay: number): number {
  return baseDelay + Math.random() * maxBaseDelay;
}

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

/** peer 证书缓存 TTL（1 小时） */
const PEER_CERT_CACHE_TTL = 3600;
const AGENT_MD_HTTP_TIMEOUT_MS = 30_000;

// ── 内部类型 ──────────────────────────────────────────────────

interface CachedPeerCert {
  certPem: string;
  validatedAt: number;
  refreshAfter: number;
}

interface V2BootstrapEntry {
  devices: Array<Record<string, unknown>>;
  auditRecipients: Array<Record<string, unknown>>;
  cachedAt: number;
  epoch?: number;
  stateCommitment?: { state_version: number; state_hash: string; state_chain: string };
  wrapPolicy?: V2WrapPolicy;
}

interface V2WrapPolicy {
  explicit: boolean;
  version: string;
  protocol: string;
  scope: 'aid' | 'device';
}

function normalizeV2WrapPolicy(raw: unknown): V2WrapPolicy {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return { explicit: false, version: '', protocol: '', scope: 'device' };
  }
  const obj = raw as Record<string, unknown>;
  let protocol = String(obj.protocol ?? '').trim().toUpperCase();
  if (protocol !== '1DH' && protocol !== '3DH') protocol = '';
  let scope = String(obj.scope ?? '').trim().toLowerCase();
  if (scope !== 'aid' && scope !== 'device') {
    scope = obj.per_aid_wrap === true ? 'aid' : 'device';
  }
  if (scope === 'aid') protocol = '1DH';
  return {
    explicit: true,
    version: String(obj.version ?? ''),
    protocol,
    scope: scope as 'aid' | 'device',
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

function applyV2WrapPolicyToTargets(targets: Target[], policy: V2WrapPolicy): Target[] {
  if (!policy.explicit) return targets;
  const out: Target[] = [];
  const seen = new Set<string>();
  for (const target of targets) {
    const row: Target = { ...target };
    if (policy.protocol === '1DH') {
      row.keySource = 'aid_master';
      row.spkPkDer = undefined;
      row.spkId = '';
    }
    if (policy.scope === 'aid') {
      const key = `${row.aid}\x1f${row.role}`;
      if (seen.has(key)) continue;
      seen.add(key);
      row.deviceId = '';
    }
    out.push(row);
  }
  return out;
}

interface V2SenderIKPendingEntry {
  msg: Record<string, unknown>;
  fromAid: string;
  senderDeviceId: string;
  groupId: string;
  createdAt: number;
}

function _v2LeftPad32(b: Uint8Array): Uint8Array {
  if (b.length === 32) return b;
  if (b.length > 32) return b.subarray(b.length - 32);
  const out = new Uint8Array(32);
  out.set(b, 32 - b.length);
  return out;
}

function _v2B64ToBytes(s: string): Uint8Array {
  const buf = Buffer.from(String(s ?? '').trim(), 'base64');
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
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

function _v2B64uToBytes(s: string): Uint8Array {
  const std = String(s ?? '').replace(/-/g, '+').replace(/_/g, '/');
  const pad = std.length % 4 === 0 ? '' : '='.repeat(4 - (std.length % 4));
  return _v2B64ToBytes(std + pad);
}

function isGroupServiceAid(value: JsonValue | object | undefined): boolean {
  const text = String(value ?? '').trim();
  if (!text.includes('.')) return false;
  const [name, ...issuerParts] = text.split('.');
  return name === 'group' && issuerParts.join('.').length > 0;
}

function formatCaughtError(error: any): Error | string {
  return error instanceof Error ? error : String(error);
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

// ── HTTP 辅助 ─────────────────────────────────────────────────

/** 发起 HTTP GET 请求，返回文本内容 */
function _httpGetText(url: string, verifySsl: boolean, timeoutMs = 30_000): Promise<string> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;
    const options: https.RequestOptions = { timeout: timeoutMs };
    if (!verifySsl) {
      options.rejectUnauthorized = false;
    }
    const req = mod.get(url, options, (res: http.IncomingMessage) => {
      if (res.statusCode && (res.statusCode < 200 || res.statusCode >= 300)) {
        reject(new Error(`HTTP ${res.statusCode} from ${url}`));
        res.resume();
        return;
      }
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`timeout fetching ${url}`));
    });
  });
}

/**
 * AUN Core SDK 主客户端
 */
function lengthPrefixedTextKey(...parts: string[]): string {
  return parts.map((part) => `${Buffer.byteLength(part, 'utf8')}:${part};`).join('');
}

function lengthPrefixedBytesKey(...parts: Uint8Array[]): Buffer {
  const chunks: Buffer[] = [];
  for (const part of parts) {
    const bytes = Buffer.from(part.buffer, part.byteOffset, part.byteLength);
    chunks.push(Buffer.from(`${bytes.length}:`, 'ascii'), bytes, Buffer.from(';', 'ascii'));
  }
  return Buffer.concat(chunks);
}

function agentMdHttpScheme(gatewayUrl: string): string {
  const raw = String(gatewayUrl ?? '').trim().toLowerCase();
  return raw.startsWith('ws://') ? 'http' : 'https';
}

function agentMdAuthority(aid: string, discoveryPort: number | null | undefined): string {
  const host = String(aid ?? '').trim();
  if (!host) return '';
  if (discoveryPort && !host.includes(':')) return `${host}:${discoveryPort}`;
  return host;
}

async function fetchWithTimeout(
  input: string,
  init: RequestInit,
  timeoutMs = AGENT_MD_HTTP_TIMEOUT_MS,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(input, { ...init, signal: controller.signal });
  } catch (error) {
    if (controller.signal.aborted) {
      throw new AUNError(`agent.md request timed out after ${timeoutMs}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function assertClientOptions(value: unknown, label: string): asserts value is AUNClientOptions | null | undefined {
  if (value == null) return;
  if (typeof value !== 'object' || Array.isArray(value) || value instanceof AID) {
    throw new ValidationError(`${label} must be an options object`);
  }
}

function clientOptionsConfig(options: AUNClientOptions | null | undefined): RpcParams {
  const raw = { ...(options ?? {}) } as Record<string, unknown>;
  if (Object.prototype.hasOwnProperty.call(raw, 'aid')) {
    throw new ValidationError('AUNClient options must not include aid; pass an AID object as the first argument');
  }
  delete raw.debug;
  delete raw.protected_headers;
  return raw as RpcParams;
}

export class AUNClient {
  /** 原始配置 */
  readonly config: RpcParams;

  /** 解析后的配置模型 */
  private _configModel: AUNConfig;

  /** 当前 AID */
  private _aid: string | null = null;

  /** 当前身份信息（内存缓存） */
  private _identity: IdentityRecord | null = null;

  /** 连接状态 */
  private _state: string = 'no_identity';

  /** 当前 AID 值对象（新 API） */
  private _currentAid: AID | null = null;

  /** 实例级 protected_headers */
  private _instanceProtectedHeaders: Record<string, string> | null = null;

  /** 重连退避时间戳（ms） */
  private _nextRetryAt: number | null = null;
  private _retryAttempt = 0;
  private _retryMaxAttempts = 0;
  private _lastError: Error | null = null;
  private _lastErrorCode: string | null = null;

  /** Gateway URL */
  private _gatewayUrl: string | null = null;

  /** 是否正在关闭 */
  private _closing = false;

  /** 事件调度器 */
  private _dispatcher: EventDispatcher;

  /** Gateway 发现 */
  private _discovery: GatewayDiscovery;

  /** 传输层 */
  private _transport: RPCTransport;

  /** 认证流程 */
  private _auth: AuthFlow;

  /** 密钥存储 */
  private _keystore: KeyStore;

  /** 会话参数（重连用） */
  private _sessionParams: ConnectParams | null = null;

  /** 会话选项 */
  private _sessionOptions: SessionOptions = { ...DEFAULT_SESSION_OPTIONS };

  /** 当前实例上下文 */
  private _deviceId: string;
  private _slotId: string;
  private _connectedAt: number = 0;
  private _connectDeliveryMode: JsonObject;
  private _defaultConnectDeliveryMode: JsonObject;

  /** peer 证书缓存 */
  private _certCache: Map<string, CachedPeerCert> = new Map();

  // AIDs 目录：{agentMdPath}/{aid}/agentmd.json 保存元数据，{agentMdPath}/{aid}/agent.md 保存正文。
  private _agentMdPath: string = '';
  private _localAgentMdPath: string = '';
  private _localAgentMdEtag: string = '';
  // gateway 在 RPC envelope._meta.agent_md_etag 注入的服务端 etag；纯观察，无下游依赖。
  private _remoteAgentMdEtag: string = '';
  private _agentMdCache: Map<string, Record<string, unknown>> = new Map();
  private _agentMdFetchInflight: Map<string, Promise<AgentMdFetchResult>> = new Map();
  private _agentMdDownloadInflight: Map<string, Promise<string>> = new Map();
  private _agentMdDownloadActive = 0;
  private _agentMdDownloadWaiters: Array<() => void> = [];

  /** 消息序列号跟踪器（群消息 + P2P 空洞检测） */
  private _seqTracker: SeqTracker = new SeqTracker();
  private _seqTrackerContext: string | null = null;

  /** 惰性群同步：已同步过的 group_id 集合 */
  private _groupSynced: Set<string> = new Set();

  /** 补洞去重：已完成/进行中的 key -> 开始时间戳，防止重复 pull 同一区间 */
  private _gapFillDone: Map<string, number> = new Map();
  /** pull gate：按消费单元串行化 public pull / gap fill / push auto-pull。 */
  private _pullGates: Map<string, { inflight: boolean; startedAt: number; token: number }> = new Map();
  private _pullResponseKeys: Map<string, number> = new Map();
  /** 当前异步调用栈是否属于通知触发的后台 RPC。 */
  private _backgroundRpcDepth = 0;
  /** 已发布到应用层的 seq 集合（按命名空间），补洞路径 publish 前检查以避免重复分发 */
  private _pushedSeqs: Map<string, Set<number>> = new Map();
  /** 已解密但因 seq 空洞暂缓发布的应用层消息（按 namespace -> seq） */
  private _pendingOrderedMsgs: Map<string, Map<number, { event: string; payload: EventPayload }>> = new Map();
  /** P2P pull 进行中到达的纯通知 push 上界；pull gate 释放后需要补拉一次。 */
  private _pendingP2pPullUpper: Map<string, number> = new Map();
  /** 缺 sender IK 时暂存原始 V2 消息，后台补齐 IK 后重试解密。 */
  private _v2SenderIKPending: Map<string, V2SenderIKPendingEntry> = new Map();
  /** sender IK 后台补齐任务去重。 */
  private _v2SenderIKFetching: Set<string> = new Set();

  // ── 后台任务定时器 ──────────────────────────────────────────
  private _heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private _tokenRefreshTimer: ReturnType<typeof setTimeout> | null = null;
  private _tokenRefreshFailures = 0;
  private _cacheCleanupTimer: ReturnType<typeof setInterval> | null = null;

  // ── V2 E2EE 状态 ──────────────────────────────────────────────
  private _v2Session?: V2Session;
  private _v2KeyStore?: V2KeyStore;
  /** V2 bootstrap 缓存：aid/group:id → 设备列表 + 时间戳 */
  private _v2BootstrapCache: Map<string, V2BootstrapEntry> = new Map();
  private _connectCapabilities: JsonObject | null = null;
  private _v2SigCache: Map<string, number> = new Map();
  private _v2StateChains: Map<string, [number, string]> = new Map();
  private _v2GroupSecurityLevels: Map<string, string> = new Map();
  /** 同一 group 的 V2 自动提案串行化，避免并发重复提交同一 state_version。 */
  private _v2AutoProposeInflight: Map<string, Promise<void>> = new Map();
  /** 同一 group 在运行中的自动提案期间收到的新触发，结束后至多再补跑一次。 */
  private _v2AutoProposePending: Set<string> = new Set();
  /** 最近一次已成功提交的 membership_snapshot；相同快照直接跳过。 */
  private _v2AutoProposeLastSnapshot: Map<string, string> = new Map();
  private _v2LazyProposeTriggered: Map<string, number> = new Map();
  private static readonly V2_BOOTSTRAP_TTL_MS = 60 * 60 * 1000;
  private static readonly V2_RETRYABLE_CODES = new Set([-33011, -33012, -33050, -33052, -33054]);
  private static readonly PULL_GATE_STALE_MS = 3000;
  /** 对端 AID 缓存（aid string → AID 对象） */
  private _peerCache = new Map<string, AID>();
  private static readonly V2_SIG_CACHE_TTL_MS = 60 * 60 * 1000;
  private static readonly V2_SIG_CACHE_MAX = 16_384;
  private static readonly AGENT_MD_DOWNLOAD_CONCURRENCY = 8;

  private _reconnectActive = false;
  private _reconnectAbort: AbortController | null = null;
  private _serverKicked = false;
  /** 缓存最近一次 gateway.disconnect 信息（含服务端附带的 detail），用于后续 connection.state 透传 */
  private _lastDisconnectInfo: { code?: any; reason?: string; detail?: Record<string, any> } | null = null;
  private _logger!: AUNLogger;
  private _clientLog!: ModuleLogger;

  constructor(aid?: AID) {
    if (typeof aid === 'string') {
      throw new ValidationError('AUNClient aid must be an AID object, not a string');
    }
    const inputAid = aid instanceof AID ? aid : null;
    const options: AUNClientOptions = {};
    const rawConfig: RpcParams = clientOptionsConfig(options);
    if (inputAid) {
      rawConfig.aun_path = inputAid.aunPath;
      rawConfig.verify_ssl = inputAid.verifySsl;
      if (inputAid.rootCaPath) rawConfig.root_ca_path = inputAid.rootCaPath;
      rawConfig.debug = inputAid.debug;
    }
    this._configModel = configFromMap(rawConfig);
    const initAid = inputAid ? inputAid.aid : null;
    this._agentMdPath = path.join(this._configModel.aunPath, 'AIDs');
    this.config = {
      aun_path: this._configModel.aunPath,
      root_ca_path: this._configModel.rootCaPath,
      seed_password: this._configModel.seedPassword,
    };
    this._deviceId = (inputAid?.deviceId) || getDeviceId(this._configModel.aunPath);

    // 初始化 Logger（per-client 单例，必须最早创建）
    const debugFlag = this._configModel.debug;
    this._logger = new AUNLogger({
      debug: debugFlag,
      aunPath: this._configModel.aunPath,
    });
    this._logger.bindDeviceId(this._deviceId);
    this._clientLog = this._logger.for('aun_core.client');
    if (debugFlag) {
      this._clientLog.info(`AUNClient initialized (debug=true, aunPath=${this._configModel.aunPath})`);
    }

    this._dispatcher = new EventDispatcher(this._logger.for('aun_core.events'));
    const dnsNet = new DnsResilientNet({
      verifySsl: this._configModel.verifySsl,
      logger: this._clientLog,
    });
    this._discovery = new GatewayDiscovery({ verifySsl: this._configModel.verifySsl, logger: this._clientLog, net: dnsNet });

    const keystore = new FileKeyStore(
      this._configModel.aunPath,
      {
        encryptionSeed: this._configModel.seedPassword ?? undefined,
        logger: this._logger.for('aun_core.keystore'),
        secretStoreLogger: this._logger.for('aun_core.secret-store'),
      },
    );
    this._keystore = keystore;

    // 启动时被动清理 registerAid 留下的孤儿临时目录（>10 分钟）
    try {
      const cleanup = (keystore as unknown as { cleanupPendingDirs?: (ms: number) => number }).cleanupPendingDirs;
      if (typeof cleanup === 'function') {
        const removed = cleanup.call(keystore, 600_000);
        if (removed > 0) {
          this._clientLog.info(`_pending cleanup removed=${removed}`);
        }
      }
    } catch (err) {
      this._clientLog.warn(`_pending cleanup failed: ${err instanceof Error ? err.message : String(err)}`);
    }

    this._slotId = inputAid?.slotId || 'default';
    this._connectDeliveryMode = normalizeDeliveryModeConfig({ mode: 'fanout' });
    this._defaultConnectDeliveryMode = { ...this._connectDeliveryMode };

    this._auth = new AuthFlow({
      keystore,
      crypto: new CryptoProvider(),
      aid: initAid,
      deviceId: this._deviceId,
      slotId: this._slotId,
      rootCaPath: this._configModel.rootCaPath ?? undefined,
      verifySsl: this._configModel.verifySsl,
      logger: this._logger.for('aun_core.auth'),
      net: dnsNet,
    });
    this._aid = initAid;

    this._transport = new RPCTransport({
      eventDispatcher: this._dispatcher,
      timeout: 10_000,
      onDisconnect: (err, closeCode) => this._handleTransportDisconnect(err, closeCode),
      verifySsl: this._configModel.verifySsl,
      logger: this._logger.for('aun_core.transport'),
      dnsNet,
    });
    this._transport.setMetaObserver((meta) => this._observeRpcMeta(meta));

    if (inputAid) {
      if (!inputAid.isPrivateKeyValid()) {
        throw new StateError('AUNClient requires an AID with a valid private key');
      }
      this._currentAid = inputAid;
      this._identity = {
        aid: inputAid.aid,
        private_key_pem: (inputAid as unknown as { _privateKeyPem?: string | null })._privateKeyPem ?? '',
        public_key_der_b64: inputAid.publicKey,
        cert: inputAid.certPem,
      };
      this._state = 'standby';
    }
    // 内部订阅：推送消息自动解密后 re-publish 给用户
    this._dispatcher.subscribe('_raw.message.received', (data) => this._onRawMessageReceived(data));
    // V2 P2P 推送通知：收到通知后自动走 message.v2.pull 拉取并解密
    this._dispatcher.subscribe('_raw.peer.v2.message_received', (data) => this._safeAsync(this._onV2PushNotification(data)));
    // V2 群组消息推送通知：收到通知后自动走 group.v2.pull 拉取并解密
    this._dispatcher.subscribe('_raw.group.v2.message_created', (data) => this._safeAsync(this._onRawGroupV2MessageCreated(data)));
    // 群组消息推送：自动解密后 re-publish
    this._dispatcher.subscribe('_raw.group.message_created', (data) => this._onRawGroupMessageCreated(data));
    // 群组变更事件：拦截处理成员变更触发的 epoch 轮换，然后透传
    this._dispatcher.subscribe('_raw.group.changed', (data) => this._onRawGroupChanged(data));
    // V2 epoch 轮换事件：清 bootstrap 缓存并触发 SPK rotation
    this._dispatcher.subscribe('_raw.group.v2.epoch_rotated', (data) => this._safeAsync(this._onV2EpochRotated(data)));
    // V2 state proposal 服务平面事件：owner/admin 负责确认或重新提案
    this._dispatcher.subscribe('_raw.group.v2.state_proposed', (data) => this._safeAsync(this._onV2StateProposed(data)));
    this._dispatcher.subscribe('_raw.group.v2.state_retry_needed', (data) => this._safeAsync(this._onV2StateRetryNeeded(data)));
    this._dispatcher.subscribe('_raw.group.v2.state_confirmed', (data) => this._safeAsync(this._onV2StateConfirmed(data)));
    // 群组状态提交事件：验证 state_hash 链并更新本地存储
    this._dispatcher.subscribe('_raw.group.state_committed', (data) => this._onGroupStateCommitted(data));
    // 其他事件直接透传
    for (const evt of ['message.recalled', 'message.ack', 'storage.object_changed']) {
      this._dispatcher.subscribe(`_raw.${evt}`, (data) => this._dispatcher.publish(evt, data));
    }
    // 服务端主动断开通知：记录日志并标记不重连
    this._dispatcher.subscribe('_raw.gateway.disconnect', (data) => this._onGatewayDisconnect(data));
  }

  // ── 属性 ──────────────────────────────────────────────────

  /** 当前 AID */
  get aid(): string | null {
    return this._aid;
  }

  /** 当前 AID 值对象 */
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

  get isReady(): boolean {
    return this.canSend;
  }

  get isOnline(): boolean {
    return this.state === ConnectionState.READY || this.state === ConnectionState.RETRY_BACKOFF || this.state === ConnectionState.RECONNECTING;
  }

  get isClosed(): boolean {
    return this.state === ConnectionState.CLOSED;
  }

  get aunPath(): string | null {
    return this.hasIdentity ? this._currentAid?.aunPath ?? this._configModel.aunPath : null;
  }

  get nextRetryAt(): Date | null {
    return this.state === ConnectionState.RETRY_BACKOFF && this._nextRetryAt ? new Date(this._nextRetryAt) : null;
  }

  get nextRetryInSeconds(): number | null {
    return this.state === ConnectionState.RETRY_BACKOFF && this._nextRetryAt ? Math.max(0, Math.ceil((this._nextRetryAt - Date.now()) / 1000)) : null;
  }

  get retryAttempt(): number {
    return this._retryAttempt;
  }

  get retryMaxAttempts(): number {
    return this._retryMaxAttempts;
  }

  get lastError(): Error | null {
    return this._lastError;
  }

  get lastErrorCode(): string | null {
    return this._lastErrorCode;
  }

  loadIdentity(aid: AID): void {
    if (!aid?.isPrivateKeyValid()) {
      throw new StateError('loadIdentity requires an AID with a valid private key');
    }
    const publicState = this.state;
    if (publicState !== ConnectionState.NO_IDENTITY && publicState !== ConnectionState.CLOSED) {
      throw new StateError(`loadIdentity not allowed in state ${publicState}`);
    }
    this._currentAid = aid;
    this._aid = aid.aid;
    this._identity = {
      aid: aid.aid,
      private_key_pem: (aid as unknown as { _privateKeyPem?: string | null })._privateKeyPem ?? '',
      public_key_der_b64: aid.publicKey,
      cert: aid.certPem,
    };
    (this._auth as unknown as { _aid?: string })._aid = aid.aid;
    this._state = 'standby';
    this._closing = false;
    this._lastError = null;
    this._lastErrorCode = null;
    this._retryAttempt = 0;
    this._nextRetryAt = null;
  }

  setProtectedHeaders(headers: Record<string, unknown> | null): void {
    if (!headers) {
      this._instanceProtectedHeaders = null;
      return;
    }
    // 字段规范：key 限 [a-z0-9_-]，_auth 为保留键不可设置。
    // 非法 key 静默跳过（不报错），值强转 str。
    const cleaned: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      const keyStr = String(key);
      if (keyStr === '_auth') continue;
      if (!/^[a-z0-9_-]+$/.test(keyStr)) continue;
      cleaned[keyStr] = value == null ? '' : String(value);
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
    return `${agentMdHttpScheme(gatewayUrl)}://${agentMdAuthority(target, this._configModel.discoveryPort)}/agent.md`;
  }

  private async _ensureAgentMdUploadToken(aid: string, gatewayUrl: string): Promise<string> {
    let identity = this._auth.loadIdentityOrNone(aid);
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

    const result = await this._auth.authenticate(gatewayUrl, { aid });
    const token = String(result.access_token ?? '');
    if (!token) throw new StateError('authenticate did not return access_token');
    this._identity = this._auth.loadIdentityOrNone(aid) ?? {
      ...identity,
      access_token: token,
      refresh_token: String(result.refresh_token ?? identity.refresh_token ?? ''),
      access_token_expires_at: typeof result.expires_at === 'number' ? result.expires_at : identity.access_token_expires_at,
      token_exp: typeof result.expires_at === 'number' ? result.expires_at : identity.token_exp,
      expires_at: typeof result.expires_at === 'number' ? result.expires_at : identity.expires_at,
    };
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

  private async _acquireAgentMdDownloadSlot(): Promise<() => void> {
    if (this._agentMdDownloadActive < AUNClient.AGENT_MD_DOWNLOAD_CONCURRENCY) {
      this._agentMdDownloadActive += 1;
      return () => this._releaseAgentMdDownloadSlot();
    }
    await new Promise<void>((resolve) => {
      this._agentMdDownloadWaiters.push(resolve);
    });
    return () => this._releaseAgentMdDownloadSlot();
  }

  private _releaseAgentMdDownloadSlot(): void {
    const next = this._agentMdDownloadWaiters.shift();
    if (next) {
      next();
      return;
    }
    if (this._agentMdDownloadActive > 0) this._agentMdDownloadActive -= 1;
  }

  private async _downloadAgentMd(aid: string): Promise<string> {
    const target = String(aid ?? '').trim();
    if (!target) throw new ValidationError('downloadAgentMd requires non-empty aid');
    const existing = this._agentMdDownloadInflight.get(target);
    if (existing) return await existing;

    const task = (async () => {
      const release = await this._acquireAgentMdDownloadSlot();
      try {
        return await this._downloadAgentMdOnce(target);
      } finally {
        release();
      }
    })();
    this._agentMdDownloadInflight.set(target, task);
    task.finally(() => {
      if (this._agentMdDownloadInflight.get(target) === task) {
        this._agentMdDownloadInflight.delete(target);
      }
    }).catch(() => undefined);
    return await task;
  }

  private async _downloadAgentMdOnce(target: string): Promise<string> {
    const cached = this._agentMdCache.get(target);
    const url = await this._resolveAgentMdUrl(target);
    let response = await fetchWithTimeout(url, {
      method: 'GET',
      headers: { Accept: 'text/markdown' },
      redirect: 'follow',
    });

    if (response.status === 304 && typeof cached?.text === 'string') {
      return String(cached.text);
    }
    if (response.status === 304) {
      response = await fetchWithTimeout(url, {
        method: 'GET',
        headers: { Accept: 'text/markdown' },
        cache: 'reload',
        redirect: 'follow',
      });
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
      redirect: 'follow',
    }, 15_000);
    const cached = this._agentMdCache.get(target) ?? {};
    const etag = String(response.headers?.get('ETag') ?? response.headers?.get('etag') ?? '').trim();
    const lastModified = String(response.headers?.get('Last-Modified') ?? response.headers?.get('last-modified') ?? '').trim();
    if (response.status === 404) {
      return { aid: target, found: false, etag: '', last_modified: '', status: 404 };
    }
    const resultEtag = response.status === 304 ? (etag || String(cached.etag ?? cached.remote_etag ?? '')) : etag;
    const resultLastModified = response.status === 304 ? (lastModified || String(cached.lastModified ?? cached.last_modified ?? '')) : lastModified;
    if (response.status < 200 || (response.status >= 300 && response.status !== 304)) {
      throw new AUNError(`head agent.md failed: HTTP ${response.status}`);
    }
    this._agentMdCache.set(target, {
      ...cached,
      etag: resultEtag,
      lastModified: resultLastModified,
      remote_etag: resultEtag,
      last_modified: resultLastModified,
    });
    return { aid: target, found: true, etag: resultEtag, last_modified: resultLastModified, status: response.status };
  }

  private async _verifyAgentMd(content: string, aid: string, certPem?: string | null): Promise<Record<string, unknown>> {
    const target = String(aid ?? '').trim();
    if (!target) throw new ValidationError('verifyAgentMd requires non-empty aid');
    let peer = target === this._currentAid?.aid ? this._currentAid : null;
    if (!peer) {
      let resolvedCert = String(certPem ?? '').trim();
      if (!resolvedCert) {
        try {
          resolvedCert = String(this._keystore.loadCert(target) ?? '').trim();
        } catch {
          resolvedCert = '';
        }
      }
      if (!resolvedCert) {
        if (!this._gatewayUrl) {
          try { this._gatewayUrl = await this._resolveGatewayForAid(target); } catch { /* best-effort before cert fetch */ }
        }
        resolvedCert = String(await this._fetchPeerCert(target) ?? '').trim();
      }
      if (!resolvedCert) throw new NotFoundError(`certificate not found for aid: ${target}`);
      peer = AID._create({
        aid: target,
        aunPath: this._configModel.aunPath,
        certPem: resolvedCert,
        privateKeyPem: null,
        certValid: true,
        privateKeyValid: false,
      });
    }
    const result = peer.verifyAgentMd(content);
    if (!result.ok) throw new AUNError((result as { ok: false; error: { message: string } }).error.message);
    const vd = (result as { ok: true; data: { status: string; payload?: string; aid?: string } }).data;
    return { ...vd, verified: vd.status === 'verified' };
  }

  /**
   * 读取 {agentMdPath}/{self_aid}/agent.md，签名后上传，并把签名结果原子写回本地。
   */
  async publishAgentMd(): Promise<Record<string, unknown>> {
    const target = this._agentMdOwnerAid();
    if (!target) {
      throw new ValidationError('publishAgentMd requires local AID');
    }
    const content = this._readAgentMdContent(target);
    const signed = this._currentAid?.signAgentMd(content);
    if (!signed?.ok) {
      throw new StateError((signed as { ok: false; error: { message: string } } | undefined)?.error.message ?? 'publishAgentMd requires a valid local AID private key');
    }
    const signedContent = signed.data.signed;
    const result = await this._uploadAgentMd(signedContent);
    this._localAgentMdEtag = this._agentMdContentEtag(signedContent);
    const remoteEtag = isJsonObject(result) ? String(result.etag ?? '').trim() : '';
    if (remoteEtag) this._remoteAgentMdEtag = remoteEtag;
    this._saveAgentMdRecord(target, {
      content: signedContent,
      local_etag: this._localAgentMdEtag,
      remote_etag: remoteEtag || undefined,
      last_modified: isJsonObject(result) ? String(result.last_modified ?? '').trim() : '',
      fetched_at: Date.now(),
      remote_status: remoteEtag ? 'found' : 'unknown',
      last_error: '',
    });
    return result as Record<string, unknown>;
  }

  private async _startAgentMdFetchTask(target: string): Promise<AgentMdFetchResult> {
    const existing = this._agentMdFetchInflight.get(target);
    if (existing) {
      return await existing;
    }

    const task = this._fetchAgentMdOnce(target);
    this._agentMdFetchInflight.set(target, task);
    task.finally(() => {
      if (this._agentMdFetchInflight.get(target) === task) {
        this._agentMdFetchInflight.delete(target);
      }
    }).catch(() => undefined);
    return await task;
  }

  private async _fetchAgentMdOnce(target: string): Promise<AgentMdFetchResult> {
    const content = await this._downloadAgentMd(target);
    const signature = await this._verifyAgentMd(content, target);

    const isSelf = target === (this._aid ?? '');
    const localEtag = this._agentMdContentEtag(content);
    const cacheMeta = this._agentMdAuthCacheMeta(target);
    const remoteEtag = String(cacheMeta.etag ?? '').trim();
    const lastModified = String(cacheMeta.lastModified ?? cacheMeta.last_modified ?? '').trim();
    if (isSelf) {
      this._localAgentMdEtag = localEtag;
      if (remoteEtag) this._remoteAgentMdEtag = remoteEtag;
    }
    const saved = this._saveAgentMdRecord(target, {
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
    let inSync: boolean | null = null;
    if (isSelf) {
      const remote = remoteEtag || this._remoteAgentMdEtag || '';
      inSync = localEtag && remote ? localEtag === remote : false;
    }

    return {
      aid: target,
      content,
      signature: signature as Record<string, unknown>,
      in_sync: inSync,
      saved_to: String(saved.saved_to ?? this._agentMdFilePath(target)),
      save_error: null,
    };
  }

  /**
   * 设置 agent.md 本地存储根目录；为空时恢复默认 {aun_path}/AIDs。
   */
  private _setAgentMdRoot(root?: string | null): string {
    const raw = String(root ?? '').trim();
    const next = raw || path.join(this._configModel.aunPath, 'AIDs');
    fs.mkdirSync(next, { recursive: true });
    this._agentMdPath = next;
    this._agentMdCache.clear();
    return this._agentMdPath;
  }

  /** 返回 setLocalAgentMdPath 计算的 etag；未设置或读取失败时返回空串。 */
  getLocalAgentMdEtag(): string {
    return this._localAgentMdEtag;
  }

  /**
   * 返回 gateway 在最近一次 RPC envelope._meta 注入的服务端 agent.md etag。
   *
   * 未收到过则为空串；不阻塞调用，纯内存读。
   */
  getRemoteAgentMdEtag(): string {
    return this._remoteAgentMdEtag;
  }


  private _agentMdContentEtag(content: string): string {
    return `"${crypto.createHash('sha256').update(String(content ?? ''), 'utf-8').digest('hex')}"`;
  }

  private _agentMdOwnerAid(): string {
    return String(this._aid ?? '').trim();
  }

  private _agentMdSafeAid(aid: string): string {
    const target = String(aid ?? '').trim();
    if (!target || target.includes('/') || target.includes('\\') || target.includes('\0')) {
      throw new ValidationError('agent.md aid is empty or contains path separators');
    }
    return target;
  }

  private _agentMdRoot(): string {
    const root = this._agentMdPath || path.join(this._configModel.aunPath, 'AIDs');
    fs.mkdirSync(root, { recursive: true });
    return root;
  }

  private _agentMdFilePath(aid: string): string {
    return path.join(this._agentMdRoot(), this._agentMdSafeAid(aid), 'agent.md');
  }

  private _agentMdMetaPath(aid: string): string {
    return path.join(this._agentMdRoot(), this._agentMdSafeAid(aid), 'agentmd.json');
  }

  private _atomicWriteText(filePath: string, content: string): void {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    const tmp = path.join(path.dirname(filePath), `.${path.basename(filePath)}.${process.pid}.${crypto.randomUUID()}.tmp`);
    let fd: number | null = null;
    try {
      fd = fs.openSync(tmp, 'w');
      fs.writeFileSync(fd, content, 'utf-8');
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = null;
      fs.renameSync(tmp, filePath);
      try {
        const dirFd = fs.openSync(path.dirname(filePath), 'r');
        try { fs.fsyncSync(dirFd); } finally { fs.closeSync(dirFd); }
      } catch { /* best effort */ }
    } finally {
      if (fd !== null) {
        try { fs.closeSync(fd); } catch { /* ignore */ }
      }
      if (fs.existsSync(tmp)) {
        try { fs.unlinkSync(tmp); } catch { /* ignore */ }
      }
    }
  }

  private _sleepSync(ms: number): void {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
  }

  private _withAgentMdRecordLock<T>(aid: string, fn: () => T): T {
    const lockPath = path.join(path.dirname(this._agentMdMetaPath(aid)), 'agentmd.json.lock');
    fs.mkdirSync(path.dirname(lockPath), { recursive: true });
    const deadline = Date.now() + 5000;
    let fd: number | null = null;
    while (fd === null) {
      try {
        fd = fs.openSync(lockPath, 'wx');
        fs.writeFileSync(fd, `${process.pid}\n`, 'utf-8');
      } catch (err: any) {
        if (err?.code !== 'EEXIST' || Date.now() >= deadline) throw err;
        try {
          const st = fs.statSync(lockPath);
          if (Date.now() - st.mtimeMs > 30000) fs.unlinkSync(lockPath);
        } catch { /* ignore */ }
        this._sleepSync(25);
      }
    }
    try {
      return fn();
    } finally {
      if (fd !== null) {
        try { fs.closeSync(fd); } catch { /* ignore */ }
      }
      try { fs.unlinkSync(lockPath); } catch { /* ignore */ }
    }
  }

  private _writeAgentMdRecordUnlocked(aid: string, record: Record<string, unknown>): void {
    const payload: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(record)) {
      if (key !== 'content' && value !== undefined && value !== null) payload[key] = value;
    }
    payload.aid = this._agentMdSafeAid(aid);
    this._atomicWriteText(this._agentMdMetaPath(aid), `${JSON.stringify(payload, null, 2)}\n`);
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

  private _readAgentMdRecordUnlocked(aid: string): Record<string, unknown> {
    const filePath = this._agentMdMetaPath(aid);
    if (!fs.existsSync(filePath)) return {};
    try {
      return this._normalizeAgentMdRecord(aid, JSON.parse(fs.readFileSync(filePath, 'utf-8')));
    } catch (err) {
      this._clientLog.warn(`agent.md metadata damaged, ignoring: aid=${aid} err=${err instanceof Error ? err.message : String(err)}`);
      return {};
    }
  }

  private _readAgentMdContent(aid: string): string {
    return fs.readFileSync(this._agentMdFilePath(aid), 'utf-8');
  }

  private _writeAgentMdContent(aid: string, content: string): string {
    const filePath = this._agentMdFilePath(aid);
    this._atomicWriteText(filePath, String(content ?? ''));
    return filePath;
  }

  private _agentMdAuthCacheMeta(aid: string): Record<string, unknown> {
    try {
      const record = this._agentMdCache.get(String(aid ?? '').trim());
      return record && typeof record === 'object' ? { ...record } : {};
    } catch {
      return {};
    }
  }

  private _loadAgentMdRecord(aid: string): Record<string, unknown> | null {
    const target = String(aid ?? '').trim();
    if (!target) return null;
    try {
      const loaded = this._withAgentMdRecordLock(target, () => {
        const record = this._readAgentMdRecordUnlocked(target);
        const next: Record<string, unknown> = Object.keys(record).length > 0 ? { ...record, aid: target } : { aid: target };
        try {
          const content = this._readAgentMdContent(target);
          next.content = content;
          next.local_etag = this._agentMdContentEtag(content);
        } catch (err) {
          if (fs.existsSync(this._agentMdMetaPath(target))) {
            this._clientLog.warn(`agent.md content read failed: aid=${target} err=${err instanceof Error ? err.message : String(err)}`);
          }
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

  private _saveAgentMdRecord(aid: string, fields: Record<string, unknown>): Record<string, unknown> {
    const target = String(aid ?? '').trim();
    if (!target) return {};
    try {
      const inputFields: Record<string, unknown> = { ...fields };
      const hasContent = Object.prototype.hasOwnProperty.call(inputFields, 'content') && inputFields.content !== undefined && inputFields.content !== null;
      let savedTo = '';
      const record = this._withAgentMdRecordLock(target, () => {
        if (hasContent) {
          const content = String(inputFields.content ?? '');
          savedTo = this._writeAgentMdContent(target, content);
          if (!inputFields.local_etag) inputFields.local_etag = this._agentMdContentEtag(content);
          if (!inputFields.fetched_at) inputFields.fetched_at = Date.now();
        }
        delete inputFields.content;
        const next: Record<string, unknown> = { ...this._readAgentMdRecordUnlocked(target), aid: target };
        for (const [key, value] of Object.entries(inputFields)) {
          if (value !== undefined && value !== null) next[key] = value;
        }
        next.updated_at = Date.now();
        this._writeAgentMdRecordUnlocked(target, next);
        return next;
      });
      const loaded: Record<string, unknown> = { ...record };
      if (hasContent) {
        loaded.content = String(fields.content ?? '');
        if (savedTo) loaded.saved_to = savedTo;
      }
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

  private _agentMdHasLocalContent(aid: string, record?: Record<string, unknown> | null): boolean {
    if (record && typeof record.content === 'string' && record.content.length > 0) return true;
    try {
      return fs.existsSync(this._agentMdFilePath(aid));
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

  private _scheduleAgentMdFetchIfMissing(aid: string, record?: Record<string, unknown> | null, source = ''): void {
    const target = String(aid ?? '').trim();
    if (!target || this._agentMdHasLocalContent(target, record)) return;
    if (this._agentMdFetchInflight.has(target)) return;
    void this._startAgentMdFetchTask(target).catch((err) => {
      this._saveAgentMdRecord(target, {
        last_error: err instanceof Error ? err.message : String(err),
        remote_status: 'found',
      });
      this._clientLog.debug(`agent.md auto fetch failed: aid=${target} source=${source || '-'} err=${err instanceof Error ? err.message : String(err)}`);
    });
  }

  private _observeAgentMdMeta(aid: string, etag = '', lastModified = '', source = ''): void {
    const target = String(aid ?? '').trim();
    const remoteEtag = String(etag ?? '').trim();
    const remoteLastModified = String(lastModified ?? '').trim();
    if (!target || (!remoteEtag && !remoteLastModified)) return;
    let before = this._agentMdCache.get(target);
    if (!before || typeof before !== 'object') before = this._loadAgentMdRecord(target) ?? {};
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
      record = this._saveAgentMdRecord(target, fields) || record;
    }
    if (target === this._agentMdOwnerAid() && remoteEtag) this._remoteAgentMdEtag = remoteEtag;
    this._scheduleAgentMdFetchIfMissing(target, record, source);
    this._clientLog.debug(`agent.md meta observed: aid=${target} etag=${remoteEtag || '-'} last_modified=${remoteLastModified || '-'} source=${source || '-'}`);
  }

  private _observeAgentMdEtag(aid: string, etag: string, source = ''): void {
    this._observeAgentMdMeta(aid, etag, '', source);
  }

  private _observeAgentMdFromEnvelope(envelope: unknown): void {
    if (!isJsonObject(envelope as JsonValue | object | null | undefined)) return;
    const env = envelope as JsonObject;
    if (!isJsonObject(env.agent_md as JsonValue | object | null | undefined)) return;
    const agentMd = env.agent_md as JsonObject;
    if (!isJsonObject(agentMd.sender as JsonValue | object | null | undefined)) return;
    const sender = agentMd.sender as JsonObject;
    let senderAid = String(sender.aid ?? '').trim();
    if (!senderAid) {
      const aad = isJsonObject(env.aad as JsonValue | object | null | undefined) ? env.aad as JsonObject : {};
      senderAid = String(aad.from ?? env.from ?? '').trim();
    }
    this._observeAgentMdMeta(
      senderAid,
      String(sender.etag ?? '').trim(),
      String(sender.last_modified ?? sender.lastModified ?? '').trim(),
      'envelope',
    );
  }

  private async _checkAgentMdCache(aid?: string | null, maxUnsyncedDays = 1): Promise<Record<string, unknown>> {
    const target = String(aid ?? this._aid ?? '').trim();
    if (!target) throw new ValidationError('checkAgentMd requires aid (or local AID)');
    const before = this._loadAgentMdRecord(target) ?? {};
    const localEtag = String(before.local_etag ?? '').trim();
    const localFound = !!(Object.keys(before).length > 0 && (String(before.content ?? '') || localEtag));
    const remoteEtagCached = String(before.remote_etag ?? '').trim();
    const lastModifiedCached = String(before.last_modified ?? '').trim();
    const checkedAt = Number(before.checked_at ?? 0);
    const fetchedAt = Number(before.fetched_at ?? 0);
    const checkedAtCached = checkedAt > 0 ? checkedAt : fetchedAt;
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
    const remoteFoundCached = !!(remoteEtagCached || String(before.remote_status ?? '') === 'found');
    if (
      !localFound &&
      !remoteFoundCached &&
      String(before.remote_status ?? '') === 'missing' &&
      this._agentMdCheckedAtFresh(checkedAtCached, maxUnsyncedDays)
    ) {
      return {
        aid: target,
        local_found: false,
        remote_found: false,
        local_etag: '',
        remote_etag: '',
        in_sync: false,
        last_modified: '',
        status: 404,
        cached: true,
        verify_status: '',
        verify_error: '',
      };
    }

    const now = Date.now();
    let remote: Record<string, unknown>;
    try {
      remote = await this._headAgentMd(target);
    } catch (err) {
      this._saveAgentMdRecord(target, { checked_at: now, remote_status: 'error', last_error: err instanceof Error ? err.message : String(err) });
      throw err;
    }
    const remoteFound = !!remote.found;
    const remoteEtag = String(remote.etag ?? '').trim();
    const lastModified = String(remote.last_modified ?? remote.lastModified ?? '').trim();
    const saved = this._saveAgentMdRecord(target, {
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
  private _observeRpcMeta(meta: Record<string, unknown>): void {
    if (!meta || typeof meta !== 'object') return;
    const etag = String(meta.agent_md_etag ?? '').trim();
    if (etag) {
      this._remoteAgentMdEtag = etag;
      this._observeAgentMdMeta(this._aid ?? '', etag, '', 'rpc.self');
    }
    const etags = meta.agent_md_etags;
    if (isJsonObject(etags as JsonValue | object | null | undefined)) {
      // role key 优先级：requester / peer 是新规范，其余是兼容旧 SDK 的别名。
      for (const key of ['requester', 'peer', 'receiver', 'target', 'to', 'sender', 'from']) {
        const item = (etags as JsonObject)[key];
        if (!isJsonObject(item as JsonValue | object | null | undefined)) continue;
        this._observeAgentMdMeta(
          String((item as JsonObject).aid ?? ''),
          String((item as JsonObject).etag ?? ''),
          String((item as JsonObject).last_modified ?? (item as JsonObject).lastModified ?? ''),
          `rpc.${key}`,
        );
      }
    }
  }
  /** 连接状态 */
  get state(): ConnectionState {
    return this._publicState(this._state);
  }

  private _publicState(state: string): ConnectionState {
    return STATE_TO_PUBLIC[state] ?? (state as ConnectionState);
  }

  /** 最近一次 gateway health check 结果，null 表示尚未检查 */
  get gatewayHealth(): boolean | null {
    return this._discovery.lastHealthy;
  }

  // ── 生命周期 ──────────────────────────────────────────────

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
      const result = await this._auth.authenticate(gateway, { aid: target });
      this._gatewayUrl = String(result.gateway ?? gateway);
      this._identity = this._auth.loadIdentityOrNone(target);
      this._state = 'authenticated';
      this._lastError = null;
      this._lastErrorCode = null;
      this._clientLog.debug(`authenticate exit: elapsed=${Date.now() - tStart}ms aid=${target}`);
      return result as Record<string, unknown>;
    } catch (err) {
      this._state = 'standby';
      this._lastError = err instanceof Error ? err : new Error(String(err));
      this._lastErrorCode = 'AUTHENTICATE_FAILED';
      this._clientLog.debug(`authenticate exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 连接到 Gateway；身份来自构造函数或 loadIdentity(aid)，认证由 SDK 内部自动完成。 */
  async connect(opts?: ConnectionOptions): Promise<void> {
    const tStart = Date.now();
    if (opts !== undefined && typeof opts === 'object') {
      const raw = opts as Record<string, unknown>;
      if ('gateway' in raw || 'access_token' in raw || 'aid' in raw || 'token' in raw) {
        throw new ValidationError('connect options must not include gateway/access_token/aid; these are managed internally');
      }
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
    const target = this._currentAid?.aid ?? this._aid ?? '';
    if (!target || !this._currentAid?.isPrivateKeyValid()) {
      throw new StateError('connect requires a loaded AID with a valid private key');
    }
    const publicState = this.state;
    const allowed = new Set<ConnectionState>([
      ConnectionState.STANDBY,
      ConnectionState.AUTHENTICATED,
      ConnectionState.RETRY_BACKOFF,
      ConnectionState.CONNECTION_FAILED,
    ]);
    if (!allowed.has(publicState)) {
      throw new StateError(`connect not allowed in state ${publicState}`);
    }
    if (publicState === ConnectionState.RETRY_BACKOFF) {
      this._stopReconnect();
    }
    // gateway 来自 authenticate() 缓存的 this._gatewayUrl；未认证则自动 authenticate()
    if (!this._gatewayUrl) {
      await this.authenticate();
    }
    this._state = 'connecting';
    const gateway = String(this._gatewayUrl ?? '').trim();
    const params = { ...options, gateway };
    const normalized = this._normalizeConnectParams(params);
    this._captureCapabilitiesFromConnect(normalized);
    this._sessionParams = normalized;
    this._sessionOptions = this._buildSessionOptions(normalized);
    const callTimeoutSec = this._sessionOptions.timeouts.call;
    this._transport.setTimeout(
      callTimeoutSec != null ? callTimeoutSec * 1000 : 35_000,
    );
    this._closing = false;
    this._clientLog.debug(`connect enter: gateway=${String(normalized.gateway ?? '')}, device_id=${this._deviceId}`);

    const gateways = this._resolveGateways(normalized);
    let lastErr: unknown = null;
    for (const gw of gateways) {
      try {
        const gwParams = { ...normalized, gateway: gw };
        await this._connectOnce(gwParams, true);
        this._lastError = null;
        this._lastErrorCode = null;
        this._clientLog.debug(`connect exit: elapsed=${Date.now() - tStart}ms aid=${this._aid ?? ''}, state=${this._state}`);
        return;
      } catch (err) {
        lastErr = err;
        if (gateways.length > 1) {
          this._clientLog.warn(`connect: gateway ${gw} failed, trying next: ${formatCaughtError(err)}`);
        }
        if (this._state !== 'closed') this._state = 'connecting';
      }
    }
    if (this._state === 'connecting' || this._state === 'authenticating') {
      this._state = 'connection_failed';
    }
    this._lastError = lastErr instanceof Error ? lastErr : new Error(String(lastErr));
    this._lastErrorCode = 'CONNECT_FAILED';
    this._clientLog.error(`connect failed: ${formatCaughtError(lastErr)}`, lastErr instanceof Error ? lastErr : undefined);
    this._clientLog.debug(`connect exit (error): elapsed=${Date.now() - tStart}ms err=${lastErr instanceof Error ? lastErr.message : String(lastErr)}`);
    throw lastErr;
  }

  /** 关闭连接 */
  async close(): Promise<void> {
    const tStart = Date.now();
    this._clientLog.debug(`close enter: state=${this._state}, aid=${this._aid ?? ''}`);
    try {
      this._closing = true;
      this._saveSeqTrackerState();
      this._stopBackgroundTasks();
      this._stopReconnect();
      if (this.state === ConnectionState.NO_IDENTITY || this.state === ConnectionState.CLOSED) {
        const closableKeyStore = this._keystore as KeyStore & { close?: () => void };
        closableKeyStore.close?.();
        this._state = 'closed';
        this._logger.close();
        this._resetSeqTrackingState();
        this._clientLog.debug(`close exit: elapsed=${Date.now() - tStart}ms (was no_identity/closed)`);
        return;
      }
      await this._transport.close();
      const closableKeyStore = this._keystore as KeyStore & { close?: () => void };
      closableKeyStore.close?.();
      this._state = 'closed';
      this._logger.close();
      await this._dispatcher.publish('state_change', { state: this._publicState(this._state) });
      this._resetSeqTrackingState();
      this._clientLog.debug(`close exit: elapsed=${Date.now() - tStart}ms`);
    } catch (err) {
      this._clientLog.debug(`close exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /**
   * 断开连接但不关闭客户端（可重新 connect，对齐 Python disconnect）。
   * disconnect 是可恢复的：停止心跳、关闭 WebSocket，但不清理 keystore 等状态。
   */
  async disconnect(): Promise<void> {
    const tStart = Date.now();
    this._clientLog.debug(`disconnect enter: state=${this._state}, aid=${this._aid ?? ''}, closing=${this._closing}`);
    try {
      // 若 close() 已在执行中，跳过 disconnect 避免竞态
      if (this._closing) {
        this._clientLog.debug(`disconnect exit: elapsed=${Date.now() - tStart}ms (closing)`);
        return;
      }
      if (![
        ConnectionState.AUTHENTICATED,
        ConnectionState.CONNECTING,
        ConnectionState.READY,
        ConnectionState.RETRY_BACKOFF,
        ConnectionState.RECONNECTING,
        ConnectionState.CONNECTION_FAILED,
      ].includes(this.state)) {
        this._clientLog.debug(`disconnect exit: elapsed=${Date.now() - tStart}ms (state=${this._state})`);
        return;
      }
      this._saveSeqTrackerState();
      this._stopBackgroundTasks();
      this._stopReconnect();
      await this._transport.close();
      this._state = 'standby';
      await this._dispatcher.publish('state_change', { state: this._publicState(this._state) });
      this._clientLog.debug(`disconnect exit: elapsed=${Date.now() - tStart}ms`);
    } catch (err) {
      this._clientLog.debug(`disconnect exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  // ── RPC ───────────────────────────────────────────────────

  /**
   * 发送 JSON-RPC 调用。
   * 自动处理内部方法限制、E2EE 加解密、客户端签名等。
   */
  async call(method: string, params?: RpcParams): Promise<RpcResult> {
    const tStart = Date.now();
    this._clientLog.debug(`call enter: method=${method}`);
    try {
    if (this.state !== ConnectionState.READY) {
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
    const rpcBackground = Boolean((p as Record<string, unknown>)._rpc_background) || this._backgroundRpcDepth > 0;
    delete (p as Record<string, unknown>)._rpc_background;
    const runWithRpcPriority = async <T>(operation: () => Promise<T> | T): Promise<T> => {
      if (!rpcBackground) return await operation();
      return await this._withBackgroundRpc(operation);
    };
    if (method === 'message.send' || method === 'group.send') {
      this._normalizeOutboundMessagePayload(p, method);
    }
    this._validateOutboundCall(method, p);
    this._injectMessageCursorContext(method, p);

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

    const pullGateLocked = Boolean((p as Record<string, unknown>)._pull_gate_locked);
    if ('_pull_gate_locked' in (p as Record<string, unknown>)) {
      delete (p as Record<string, unknown>)._pull_gate_locked;
    }
    const pullGateKey = this._pullGateKeyForCall(method, p);
    if (pullGateKey && this._isPullResponseProcessing(pullGateKey)) {
      this._clientLog.debug(`pull skipped while processing pull response: method=${method} key=${pullGateKey}`);
      return this._emptyPullResultForCall(method);
    }
    if (pullGateKey && !pullGateLocked) {
      const lockedParams = { ...p, _pull_gate_locked: true };
      if (rpcBackground) (lockedParams as Record<string, unknown>)._rpc_background = true;
      const result = await this._runPullSerialized(pullGateKey, async () => this.call(method, lockedParams));
      return result as RpcResult;
    }

    // 自动加密：message.send 默认加密（encrypt 默认 true）— V2-only
    if (method === 'message.send') {
      const encrypt = p.encrypt ?? true;
      delete p.encrypt;
      if (encrypt) {
        return await runWithRpcPriority(() => this._sendV2(String(p.to ?? ''), p.payload as Record<string, unknown>, {
          messageId: String(p.message_id ?? '') || undefined,
          timestamp: p.timestamp as number | undefined,
          protectedHeaders: this._protectedHeadersFromParams(p) as Record<string, unknown> | undefined,
          context: isJsonObject(p.context) ? p.context : undefined,
        })) as RpcResult;
      }
      // encrypt=false：明文走通用 RPC 路径；protected_headers/headers 是信封元数据，加密与否都保留
      this._maybeAppendEchoTraceSend(p);
    }

    // 自动加密：group.send 默认加密（encrypt 默认 true）— V2-only
    if (method === 'group.send') {
      const encrypt = p.encrypt ?? true;
      delete p.encrypt;
      if (encrypt) {
        return await runWithRpcPriority(() => this._sendGroupV2(String(p.group_id ?? ''), p.payload as Record<string, unknown>, {
          messageId: String(p.message_id ?? '') || undefined,
          timestamp: p.timestamp as number | undefined,
          protectedHeaders: this._protectedHeadersFromParams(p) as Record<string, unknown> | undefined,
          context: isJsonObject(p.context) ? p.context : undefined,
        })) as RpcResult;
      }
      this._maybeAppendEchoTraceSend(p);
    }
    if (method === 'group.thought.put') {
      const encrypt = p.encrypt ?? true;
      delete p.encrypt;
      if (encrypt) {
        const v2Error = 'V2 session not initialized; encrypted group.thought.put requires V2 (V1 E2EE removed)';
        if (!this._v2Session || !String(p.group_id ?? '').trim()) {
          throw new StateError(v2Error);
        }
        return await runWithRpcPriority(() => this._putGroupThoughtEncryptedV2(p));
      }
    }
    if (method === 'message.thought.put') {
      const encrypt = p.encrypt ?? true;
      delete p.encrypt;
      if (encrypt) {
        await this._ensureV2SessionReady(
          'message.thought.put',
          'V2 session not initialized; encrypted message.thought.put requires V2 (V1 E2EE removed)',
        );
        return await runWithRpcPriority(() => this._putMessageThoughtEncryptedV2(p));
      }
    }

    // V2-only：兼容入口名只作为 SDK 内部适配层存在，底层绝不能降级发 legacy RPC。
    if (method === 'message.pull' || method === 'message.v2.pull') {
      await this._ensureV2SessionReady('message.pull');
      const skipAutoAck = p._skip_auto_ack === true || p.skip_auto_ack === true;
      const force = p.force === true;
      const afterSeq = Number(p.after_seq ?? 0) || 0;
      const limit = Number(p.limit ?? 50) || 50;
      const messages = skipAutoAck
        ? await runWithRpcPriority(() => this._pullV2(afterSeq, limit, { skipAutoAck: true, gateLocked: true, force }))
        : await runWithRpcPriority(() => this._pullV2(afterSeq, limit, { gateLocked: true, force }));
      return { messages } as RpcResult;
    }

    if (method === 'message.ack' || method === 'message.v2.ack') {
      await this._ensureV2SessionReady('message.ack');
      return await runWithRpcPriority(() => this._ackV2(Number(p.seq ?? p.up_to_seq ?? 0) || undefined)) as RpcResult;
    }

    if (method === 'group.pull' || method === 'group.v2.pull') {
      if (!String(p.group_id ?? '').trim()) {
        throw new ValidationError('group.pull requires group_id');
      }
      await this._ensureV2SessionReady('group.pull');
      const messages = await runWithRpcPriority(() => this._pullGroupV2(
        String(p.group_id),
        Number(p.after_seq ?? p.after_message_seq ?? 0) || 0,
        Number(p.limit ?? 50) || 50,
        { gateLocked: true },
      ));
      return { messages } as RpcResult;
    }

    if (method === 'group.ack_messages' || method === 'group.v2.ack') {
      if (!String(p.group_id ?? '').trim()) {
        throw new ValidationError('group.ack_messages requires group_id');
      }
      await this._ensureV2SessionReady('group.ack_messages');
      return await runWithRpcPriority(() => this._ackGroupV2(
        String(p.group_id),
        Number(p.seq ?? p.msg_seq ?? p.up_to_seq ?? 0) || undefined,
      )) as RpcResult;
    }

    if (method === 'message.pull') {
      delete p._skip_auto_ack;
      delete p.skip_auto_ack;
    }

    // 关键操作自动附加客户端签名
    if (SIGNED_METHODS.has(method)) {
      if (this._shouldSkipClientSignature(method, p)) {
        delete p.client_signature;
      } else {
        this._signClientOperation(method, p);
      }
    }

    // P1-23: 非幂等方法使用更长超时
    const callTimeout = NON_IDEMPOTENT_METHODS.has(method) ? NON_IDEMPOTENT_TIMEOUT_MS : undefined;
    if (method === 'group.thought.get' || method === 'message.thought.get') {
      this._clientLog.debug(`thought.get transport call start: method=${method}, params=${this._debugJson(this._messageEnvelopeFieldsForDebug(p))}`);
    }
    let result = callTimeout
      ? (
        rpcBackground
          ? await this._transport.call(method, p, callTimeout, undefined, true)
          : await this._transport.call(method, p, callTimeout)
      )
      : (
        rpcBackground
          ? await this._transport.call(method, p, undefined, undefined, true)
          : await this._transport.call(method, p)
      );

    if (method === 'group.thought.get' && isJsonObject(result)) {
      this._clientLog.debug(`group.thought.get transport result: found=${String((result as JsonObject).found ?? '')}, raw_count=${Array.isArray((result as JsonObject).thoughts) ? ((result as JsonObject).thoughts as unknown[]).length : 0}`);
      result = await this._decryptGroupThoughts(result);
    }
    if (method === 'message.thought.get' && isJsonObject(result)) {
      this._clientLog.debug(`message.thought.get transport result: found=${String((result as JsonObject).found ?? '')}, raw_count=${Array.isArray((result as JsonObject).thoughts) ? ((result as JsonObject).thoughts as unknown[]).length : 0}`);
      result = await this._decryptMessageThoughts(result);
    }

    // ── V2-only 群状态编排：成员变更后 propose+confirm state。
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
      }
    }

    this._clientLog.debug(`call exit: method=${method} elapsed=${Date.now() - tStart}ms`);
    return result;
    } catch (err) {
      this._clientLog.debug(`call exit (error): method=${method} elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  // ── 事件 ──────────────────────────────────────────────────

  /** 订阅事件 */
  on(event: string, handler: EventHandler): Subscription {
    const tStart = Date.now();
    this._clientLog.debug(`on enter: event=${event}`);
    const result = this._dispatcher.subscribe(event, handler);
    this._clientLog.debug(`on exit: elapsed=${Date.now() - tStart}ms event=${event}`);
    return result;
  }

  private async _callRawV2Rpc(method: string, params?: RpcParams): Promise<RpcResult> {
    const p: RpcParams = { ...(params ?? {}) };
    const rpcBackground = Boolean((p as Record<string, unknown>)._rpc_background) || this._backgroundRpcDepth > 0;
    delete (p as Record<string, unknown>)._rpc_background;
    delete p._pull_gate_locked;
    delete p._skip_auto_ack;
    delete p.skip_auto_ack;

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
        this._signClientOperation(method, p);
      }
    }
    return rpcBackground
      ? await this._transport.call(method, p, undefined, undefined, true)
      : await this._transport.call(method, p);
  }

  /** P2-13: 取消订阅事件（对齐 Python/JS off 方法） */
  off(event: string, handler: EventHandler): void {
    const tStart = Date.now();
    this._clientLog.debug(`off enter: event=${event}`);
    this._dispatcher.unsubscribe(event, handler);
    this._clientLog.debug(`off exit: elapsed=${Date.now() - tStart}ms event=${event}`);
  }

  // ── E2EE V2 公共辅助 ─────────────────────────────────────

  private _protectedHeadersFromParams(params: RpcParams): ProtectedHeadersInput {
    const value = params.protected_headers ?? params.headers;
    if (value == null) return null;
    if (isJsonObject(value)) return value;
    const maybeHeaders = value as unknown as { toObject?: () => unknown };
    if (typeof value === 'object' && typeof maybeHeaders.toObject === 'function') {
      const obj = maybeHeaders.toObject();
      return isJsonObject(obj as JsonValue | object | null | undefined) ? obj as Record<string, unknown> : null;
    }
    return null;
  }
  // ── 客户端签名 ────────────────────────────────────────────

  /**
   * 为关键操作附加客户端 ECDSA 签名（client_signature 字段）。
   * 签名覆盖所有非 _ 前缀且非 client_signature 的业务字段。
   */
  private _signClientOperation(method: string, params: RpcParams): void {
    const identity = this._identity;
    if (!identity || !identity.private_key_pem) return;

    try {
      const aid = String(identity.aid ?? '');
      const ts = String(Math.floor(Date.now() / 1000));

      // 计算 params hash — 必须递归排序所有键（与 Python json.dumps(sort_keys=True, separators=(",",":")) 一致）
      const paramsForHash: RpcParams = {};
      for (const [k, v] of Object.entries(params)) {
        if (k !== 'client_signature' && !k.startsWith('_')) {
          paramsForHash[k] = v;
        }
      }
      const paramsJson = stableStringify(paramsForHash);
      const paramsHash = crypto.createHash('sha256').update(paramsJson, 'utf-8').digest('hex');

      const signData = Buffer.from(`${method}|${aid}|${ts}|${paramsHash}`, 'utf-8');
      const privateKey = crypto.createPrivateKey(String(identity.private_key_pem));
      const signature = crypto.sign('SHA256', signData, privateKey);

      // 证书指纹
      let certFingerprint = '';
      const certPem = String(identity.cert ?? '');
      if (certPem) {
        const certObj = new crypto.X509Certificate(certPem);
        certFingerprint = 'sha256:' + certObj.fingerprint256.replace(/:/g, '').toLowerCase();
      }

      params.client_signature = {
        aid,
        cert_fingerprint: certFingerprint,
        timestamp: ts,
        params_hash: paramsHash,
        signature: signature.toString('base64'),
      };
    } catch (exc) {
      throw new Error(`客户端签名失败，拒绝发送无签名请求: ${formatCaughtError(exc)}`);
    }
  }

  // ── 事件自动解密管线 ──────────────────────────────────────

  /** 处理 transport 层推送的原始 P2P 消息 */
  private async _onRawMessageReceived(data: EventPayload): Promise<void> {
    const tStart = Date.now();
    if (isJsonObject(data)) {
      this._logMessageDebug('server-push', '_raw.message.received', 'message.received', data);
      this._clientLog.debug(`_onRawMessageReceived enter: from=${String(data.from ?? '')}, message_id=${String(data.message_id ?? '')}, seq=${String(data.seq ?? '')}`);
    } else {
      this._clientLog.debug(`_onRawMessageReceived enter: non-object payload`);
    }
    // 异步处理，不阻塞事件调度
    this._processAndPublishMessage(data).catch((exc) => {
      this._clientLog.warn(`P2P message decrypt failed: ${formatCaughtError(exc)}`);
      // H26: 不再投递原始密文 payload；改发 message.undecryptable 事件，仅携带安全 header
      if (isJsonObject(data)) {
        const safeEvent = {
          message_id: data.message_id,
          from: data.from,
          to: data.to,
          seq: data.seq,
          timestamp: data.timestamp,
          _decrypt_error: String(exc),
        };
        this._attachV2EnvelopeMetadataFromSource(safeEvent as JsonObject, data);
        Promise.resolve(this._publishAppEvent('message.undecryptable', safeEvent)).catch(() => {});
      }
    });
    this._clientLog.debug(`_onRawMessageReceived exit: elapsed=${Date.now() - tStart}ms (handler dispatched)`);
  }

  /** 实际处理推送消息的异步任务 */
  private async _processAndPublishMessage(data: EventPayload): Promise<void> {
    if (!isJsonObject(data)) {
      await this._publishAppEvent('message.received', data, 'push');
      return;
    }
    const msg: Message = { ...data };
    if (!this._messageTargetsCurrentInstance(msg)) {
      this._clientLog.debug(`P2P push filtered by instance: message_id=${String(msg.message_id ?? '')}, seq=${String(msg.seq ?? '')}, target_device=${String(msg.device_id ?? '')}, target_slot=${String(msg.slot_id ?? '')}, local_device=${this._deviceId}, local_slot=${this._slotId}`);
      return;
    }

    const encryptedPush = this._isEncryptedPushMessage(msg);
    // P2P 空洞检测
    const seq = msg.seq as number | undefined;
    if (seq !== undefined && seq !== null && this._aid) {
      const ns = `p2p:${this._aid}`;
      // Push 只先更新 maxSeenSeq；contiguous_seq 是已交付游标，必须等应用层发布返回后再推进。
      if (seq > 0) this._seqTracker.updateMaxSeen(ns, seq);
      const contigBefore = this._seqTracker.getContiguousSeq(ns);
      const published = encryptedPush
        ? await this._publishEncryptedPushMessage('message.received', 'message.undecryptable', ns, seq, msg, false)
        : await this._publishOrderedMessage('message.received', ns, seq, msg);
      const contigAfter = this._seqTracker.getContiguousSeq(ns);
      const needPull = Number(seq) > contigAfter && !published;
      if (needPull) {
        this._clientLog.debug(`P2P seq gap detected: ns=${ns}, seq=${seq}, contiguous=${contigAfter}`);
        this._fillP2pGap().catch(exc => this._clientLog.warn(`background gap fill trigger failed: ${formatCaughtError(exc)}`));
      }
      // auto-ack contiguous_seq
      const contig = this._seqTracker.getContiguousSeq(ns);
      if (contig > 0) {
        const maxSeen = this._seqTracker.getMaxSeenSeq(ns);
        const ackSeq = maxSeen > 0 ? Math.min(contig, maxSeen) : contig;
        this._clientLog.debug(`P2P push auto-ack send: ns=${ns}, seq=${ackSeq}, contiguous=${contig}, max_seen=${maxSeen}`);
          this._withBackgroundRpc(() => this._ackV2(ackSeq))
            .then(() => { this._clientLog.debug(`P2P push auto-ack ok: ns=${ns}, seq=${ackSeq}`); })
            .catch((e) => { this._clientLog.debug(`P2P auto-ack failed: ${formatCaughtError(e)}`); });
      }
      // 即时持久化 cursor，异常断连后不回退
      if (contigAfter !== contigBefore) this._saveSeqTrackerState();
      if (encryptedPush) return;
    } else {
      if (encryptedPush) {
        await this._publishEncryptedPushMessage('message.received', 'message.undecryptable', '', seq ?? 0, msg, false);
        return;
      }
      // V2-only：普通 _raw.message.received 只承载明文；V2 密文由 peer.v2.message_received 通知触发 pull。
      await this._publishAppEvent('message.received', msg, 'push');
    }
  }

  /** 处理群组消息推送：自动解密后 re-publish */
  private async _onRawGroupMessageCreated(data: EventPayload): Promise<void> {
    const tStart = Date.now();
    if (isJsonObject(data)) {
      this._logMessageDebug('server-push', '_raw.group.message_created', 'group.message_created', data);
      this._clientLog.debug(`_onRawGroupMessageCreated enter: group_id=${String(data.group_id ?? '')}, message_id=${String(data.message_id ?? '')}, seq=${String(data.seq ?? '')}`);
    } else {
      this._clientLog.debug(`_onRawGroupMessageCreated enter: non-object payload`);
    }
    this._processAndPublishGroupMessage(data).catch((exc) => {
      this._clientLog.warn(`group message decrypt failed: ${formatCaughtError(exc)}`);
      // H26: 不再投递原始密文 payload；改发 group.message_undecryptable 事件
      if (isJsonObject(data)) {
        const safeEvent = {
          message_id: data.message_id,
          group_id: data.group_id,
          from: data.from,
          seq: data.seq,
          timestamp: data.timestamp,
          _decrypt_error: String(exc),
        };
        this._attachV2EnvelopeMetadataFromSource(safeEvent as JsonObject, data);
        Promise.resolve(this._publishAppEvent('group.message_undecryptable', safeEvent)).catch(() => {});
      }
    });
    this._clientLog.debug(`_onRawGroupMessageCreated exit: elapsed=${Date.now() - tStart}ms (handler dispatched)`);
  }

  /**
   * 处理群组推送消息的异步任务。
   *
   * 带 payload 的事件（消息推送）：解密后 re-publish。
   * 不带 payload 的事件（通知）：自动 pull 最新消息，逐条解密后 re-publish。
   */
  private async _processAndPublishGroupMessage(data: EventPayload): Promise<void> {
    if (!isJsonObject(data)) {
      await this._publishAppEvent('group.message_created', data, 'group-push');
      return;
    }
    const msg: Message = { ...data };
    const groupId = (msg.group_id ?? '') as string;
    const seq = msg.seq as number | undefined;
    const payload = msg.payload;

    if (groupId) {
      this._groupSynced.add(groupId);  // 收到推送即视为已激活
    }

    if (payload === undefined || payload === null
      || (typeof payload === 'object' && Object.keys(payload as object).length === 0)) {
      // 不带 payload 的通知不能先推进 seq，否则 auto-pull 会用推进后的 cursor 跳过该消息。
      void this._autoPullGroupMessages(msg).catch((exc) => {
        this._clientLog.warn(`auto pull group message task failed: ${formatCaughtError(exc)}`);
      });
      return;
    }
    const encryptedPush = this._isEncryptedPushMessage(msg);
    if (groupId && seq !== undefined && seq !== null) {
      const ns = `group:${groupId}`;
      // Push 只先更新 maxSeenSeq；contiguous_seq 是已交付游标，必须等应用层发布返回后再推进。
      if (seq > 0) this._seqTracker.updateMaxSeen(ns, seq);
      const contigBefore = this._seqTracker.getContiguousSeq(ns);
      const published = encryptedPush
        ? await this._publishEncryptedPushMessage('group.message_created', 'group.message_undecryptable', ns, seq, msg, true)
        : await this._publishOrderedMessage('group.message_created', ns, seq, msg);
      const contigAfter = this._seqTracker.getContiguousSeq(ns);
      const needPull = Number(seq) > contigAfter && !published;
      if (needPull) {
        this._clientLog.debug(`group message seq gap detected: group=${groupId}, seq=${seq}, contiguous=${contigAfter}`);
        this._fillGroupGap(groupId).catch(exc => this._clientLog.warn(`background gap fill trigger failed: ${formatCaughtError(exc)}`));
      }
      const contig = this._seqTracker.getContiguousSeq(ns);
      if (contig > 0) {
        const maxSeen = this._seqTracker.getMaxSeenSeq(ns);
        const ackSeq = maxSeen > 0 ? Math.min(contig, maxSeen) : contig;
        this._clientLog.debug(`group push auto-ack send: group=${groupId}, ns=${ns}, seq=${ackSeq}, contiguous=${contig}, max_seen=${maxSeen}`);
          this._withBackgroundRpc(() => this._ackGroupV2(groupId, ackSeq))
            .then(() => { this._clientLog.debug(`group push auto-ack ok: group=${groupId}, seq=${ackSeq}`); })
            .catch((e) => { this._clientLog.debug(`group message auto-ack failed: group=${groupId} ${formatCaughtError(e)}`); });
      }
      if (contigAfter !== contigBefore) this._saveSeqTrackerState();
      if (encryptedPush) return;
    } else {
      if (encryptedPush) {
        await this._publishEncryptedPushMessage('group.message_created', 'group.message_undecryptable', '', seq ?? 0, msg, true);
        return;
      }
      // V2-only：普通 group.message_created 只承载明文；V2 密文由 group.v2.message_created 通知触发 pull。
      await this._publishAppEvent('group.message_created', msg, 'group-push');
    }
  }

  /** 收到不带 payload 的 group.message_created 通知后，自动 pull 最新消息 */
  private async _autoPullGroupMessages(notification: Message): Promise<void> {
    let groupId = String(notification.group_id ?? '').trim();
    if (!groupId) {
      await this._publishAppEvent('group.message_created', notification);
      return;
    }
    groupId = normalizeGroupId(groupId) || groupId;
    const ns = `group:${groupId}`;
    const afterSeq = this._seqTracker.getContiguousSeq(ns);
    this._clientLog.debug(`auto pull group messages start: group=${groupId}, after_seq=${afterSeq}, seq=${String(notification.seq ?? '')}`);
    const started = await this._tryRunBackgroundPull(ns, async () => {
      const pullAfterSeq = this._seqTracker.getContiguousSeq(ns);
      const messages = await this._pullGroupV2(groupId, pullAfterSeq, 50, { gateLocked: true });
      this._prunePushedSeqs(ns);
      return messages.length;
    }, true);
    if (!started) {
      this._clientLog.debug(`auto pull group messages skipped: pull in-flight group=${groupId}`);
    }
  }

  /** 后台补齐群消息空洞 */
  private async _fillGroupGap(groupId: string): Promise<void> {
    groupId = normalizeGroupId(groupId) || String(groupId ?? '').trim();
    if (!groupId) return;
    const ns = `group:${groupId}`;
    const afterSeq = this._seqTracker.getContiguousSeq(ns);
    // 去重：同一 (group:id:after_seq) 只补一次
    const dedupKey = `group_msg:${groupId}:${afterSeq}`;
    if (this._gapFillDone.has(dedupKey)) return;
    const token = this._tryAcquirePullGate(ns);
    if (token === null) {
      this._clientLog.debug(`group message gap fill skipped: pull in-flight group=${groupId}`);
      return;
    }
    this._gapFillDone.set(dedupKey, Date.now());
    this._clientLog.debug(`group message gap fill start: group=${groupId}, after_seq=${afterSeq}`);
    let filled = 0;
    try {
      const messages = await this._withBackgroundRpc(() => this._pullGroupV2(groupId, afterSeq, 50, { gateLocked: true }));
      filled = messages.length;
      this._prunePushedSeqs(ns);
      if (this._seqTracker.getContiguousSeq(ns) !== afterSeq) {
        await this._drainOrderedMessages(ns, undefined, true);
        this._saveSeqTrackerState();
      }
      this._clientLog.debug(`group message gap fill done: group=${groupId}, after_seq=${afterSeq}, filled=${filled}`);
    } catch (exc) {
      this._clientLog.warn(`group message gap fill failed: ${formatCaughtError(exc)}`);
    } finally {
      this._gapFillDone.delete(dedupKey);
      this._releasePullGate(ns, token);
      if (filled > 0 && this._seqTracker.getContiguousSeq(ns) > afterSeq) {
        void this._fillGroupGap(groupId);
      }
    }
  }

  /** 后台补齐 P2P 消息空洞 */
  private async _fillP2pGap(): Promise<void> {
    if (!this._aid) return;
    const ns = `p2p:${this._aid}`;
    const afterSeq = this._seqTracker.getContiguousSeq(ns);
    // 去重：同一 (type:after_seq) 只补一次
    const dedupKey = `p2p:${afterSeq}`;
    if (this._gapFillDone.has(dedupKey)) return;
    const token = this._tryAcquirePullGate(ns);
    if (token === null) {
      this._clientLog.debug(`P2P message gap fill skipped: pull in-flight ns=${ns}`);
      return;
    }
    this._gapFillDone.set(dedupKey, Date.now());
    this._clientLog.debug(`P2P message gap fill start: after_seq=${afterSeq}`);
    let filled = 0;
    try {
      const messages = await this._withBackgroundRpc(() => this._pullV2(afterSeq, 50, { skipAutoAck: true, gateLocked: true }));
      filled = messages.length;
      this._prunePushedSeqs(ns);
      if (this._seqTracker.getContiguousSeq(ns) !== afterSeq) {
        await this._drainOrderedMessages(ns, undefined, true);
        this._saveSeqTrackerState();
      }
      const contig = this._seqTracker.getContiguousSeq(ns);
      if (contig > 0 && contig !== afterSeq) {
        await this._withBackgroundRpc(() => this._ackV2(contig));
      }
      this._clientLog.debug(`P2P message gap fill done: after_seq=${afterSeq}, filled=${filled}`);
    } catch (exc) {
      this._clientLog.warn(`P2P message gap fill failed: ${formatCaughtError(exc)}`);
    } finally {
      this._gapFillDone.delete(dedupKey);
      this._releasePullGate(ns, token);
      if (filled > 0 && this._seqTracker.getContiguousSeq(ns) > afterSeq) {
        void this._fillP2pGap();
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

  private _recordPendingP2pPull(ns: string, seq: number): void {
    if (!ns || seq <= 0) return;
    const previous = this._pendingP2pPullUpper.get(ns) ?? 0;
    if (seq > previous) {
      this._pendingP2pPullUpper.set(ns, seq);
    }
    this._clientLog.debug(`P2P pending pull upper recorded: ns=${ns}, seq=${seq}, previous=${previous}, contiguous=${this._seqTracker.getContiguousSeq(ns)}`);
  }

  private _schedulePendingP2pPullIfNeeded(ns: string, reason: string): boolean {
    if (!ns) return false;
    const upperSeq = this._pendingP2pPullUpper.get(ns) ?? 0;
    if (upperSeq <= 0) {
      this._pendingP2pPullUpper.delete(ns);
      return false;
    }
    const contig = this._seqTracker.getContiguousSeq(ns);
    if (upperSeq <= contig) {
      this._pendingP2pPullUpper.delete(ns);
      this._clientLog.debug(`P2P pending pull upper already covered: ns=${ns}, upper_seq=${upperSeq}, contiguous=${contig}, reason=${reason}`);
      return false;
    }
    if (this.state !== ConnectionState.READY || this._closing) {
      this._clientLog.debug(`P2P pending pull postponed: ns=${ns}, upper_seq=${upperSeq}, contiguous=${contig}, state=${this._state}, closing=${this._closing}, reason=${reason}`);
      return false;
    }
    this._pendingP2pPullUpper.delete(ns);
    this._clientLog.info(`P2P pending push follow-up pull scheduled: ns=${ns}, upper_seq=${upperSeq}, contiguous=${contig}, reason=${reason}`);
    void this._fillP2pGap();
    return true;
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

  private _publishAppEvent(event: string, payload: EventPayload, source = 'direct'): void | Promise<void> {
    if ((event === 'message.received' || event === 'group.message_created') && isJsonObject(payload)) {
      this._maybeAppendEchoTraceReceive(payload as Record<string, unknown>);
    }
    this._logAppMessagePublish(event, payload, source);
    // 注入本地/远端 agent.md etag，让应用层判断版本一致性；失败不影响业务。
    if (isJsonObject(payload)) {
      try {
        const localEtag = this._localAgentMdEtag || '';
        const remoteEtag = this._remoteAgentMdEtag || '';
        if (localEtag || remoteEtag) {
          const obj = payload as Record<string, unknown>;
          if (!('_agent_md' in obj)) {
            obj._agent_md = {
              local_etag: localEtag,
              remote_etag: remoteEtag,
            };
          }
        }
      } catch (err) {
        this._clientLog.debug(`agent_md etag inject skipped: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    return this._dispatcher.publishSyncAware(event, this._normalizePublishedMessagePayload(event, payload));
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

  private _debugJson(value: unknown): string {
    const seen = new WeakSet<object>();
    try {
      return JSON.stringify(value, (_key, item) => {
        if (typeof item === 'bigint') return item.toString();
        if (item instanceof Uint8Array) {
          return {
            _type: item.constructor.name,
            len: item.byteLength,
            base64: Buffer.from(item).toString('base64'),
          };
        }
        if (item && typeof item === 'object') {
          if (seen.has(item as object)) return '[Circular]';
          seen.add(item as object);
        }
        return item;
      });
    } catch {
      return String(value);
    }
  }

  private _messagePayloadForDebug(message: unknown): unknown {
    if (!isJsonObject(message as JsonValue | object | null | undefined)) return message;
    const msg = message as JsonObject;
    if ('payload' in msg) return msg.payload;
    if ('content' in msg) return msg.content;
    if (typeof msg.envelope_json === 'string' && msg.envelope_json) {
      try {
        return JSON.parse(msg.envelope_json) as unknown;
      } catch {
        return msg.envelope_json;
      }
    }
    if (isJsonObject(msg.legacy_v1 as JsonValue | object | null | undefined)) {
      const legacy = msg.legacy_v1 as JsonObject;
      if ('payload' in legacy) return legacy.payload;
      if ('content' in legacy) return legacy.content;
    }
    return null;
  }

  private _messageEnvelopeFieldsForDebug(message: unknown): Record<string, unknown> {
    if (!isJsonObject(message as JsonValue | object | null | undefined)) {
      return { value_type: typeof message };
    }
    const msg = message as JsonObject;
    const keys = [
      'message_id', 'id', 'from', 'from_aid', 'sender_aid', 'to', 'to_aid',
      'group_id', 'seq', 'msg_seq', 'type', 'version', 'timestamp', 't_server',
      'device_id', 'slot_id', 'encrypted', 'dispatch_mode', 'dispatch',
      'e2ee', 'headers', 'protected_headers', 'context', 'status',
      '_decrypt_error', '_decrypt_stage',
    ];
    const out: Record<string, unknown> = {};
    for (const key of keys) {
      if (Object.prototype.hasOwnProperty.call(msg, key)) out[key] = msg[key];
    }
    return out;
  }

  private _logMessageDebug(
    stage: string,
    source: string,
    event: string,
    message: unknown,
    opts: { payloadOverride?: unknown; extra?: Record<string, unknown> } = {},
  ): void {
    // 关键消息链路诊断日志长期保留在代码中；是否输出由 logger 的 debug/level 控制。
    const record: Record<string, unknown> = {
      stage,
      source,
      event,
      envelope: this._messageEnvelopeFieldsForDebug(message),
      payload: opts.payloadOverride !== undefined ? opts.payloadOverride : this._messagePayloadForDebug(message),
    };
    if (opts.extra) record.extra = opts.extra;
    this._clientLog.debug(`message.debug ${this._debugJson(record)}`);
  }

  private _logAppMessagePublish(event: string, payload: unknown, source: string): void {
    if (!['message.received', 'message.undecryptable', 'group.message_created', 'group.message_undecryptable'].includes(event)) {
      return;
    }
    this._logMessageDebug('publish', source, event, payload);
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
      if (targetSlotId !== this._slotId) {
        return false;
      }
    }
    return true;
  }

  private _tryAcquirePullGate(key: string): number | null {
    if (!key) return 0;
    const now = Date.now();
    const gate = this._pullGates.get(key) ?? { inflight: false, startedAt: 0, token: 0 };
    if (gate.inflight && now - gate.startedAt <= AUNClient.PULL_GATE_STALE_MS) {
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
    if (key.startsWith('p2p:')) {
      this._schedulePendingP2pPullIfNeeded(key, 'pull-gate-release');
    }
  }

  private _pullGateKeyForCall(method: string, params: RpcParams): string {
    if (method === 'message.pull' || method === 'message.v2.pull') {
      return this._aid ? `p2p:${this._aid}` : '';
    }
    if ((method === 'group.pull' || method === 'group.v2.pull') && String(params.group_id ?? '').trim()) {
      return `group:${String(params.group_id ?? '').trim()}`;
    }
    if (method === 'group.pull_events' && String(params.group_id ?? '').trim()) {
      return `group_event:${String(params.group_id ?? '').trim()}`;
    }
    return '';
  }

  private _isPullResponseProcessing(key: string): boolean {
    if (!key) return false;
    return (this._pullResponseKeys.get(key) ?? 0) > 0;
  }

  private _emptyPullResultForCall(method: string): RpcResult {
    if (method === 'group.pull_events') return { events: [], count: 0 } as RpcResult;
    if (method === 'message.pull' || method === 'message.v2.pull' || method === 'group.pull' || method === 'group.v2.pull') {
      return { messages: [], count: 0 } as RpcResult;
    }
    return {} as RpcResult;
  }

  private _withPullResponseProcessing<T>(key: string, fn: () => Promise<T> | T): T | Promise<T> {
    if (!key) return fn();
    this._pullResponseKeys.set(key, (this._pullResponseKeys.get(key) ?? 0) + 1);
    const release = (): void => {
      const next = (this._pullResponseKeys.get(key) ?? 1) - 1;
      if (next <= 0) {
        this._pullResponseKeys.delete(key);
      } else {
        this._pullResponseKeys.set(key, next);
      }
    };
    try {
      const result = fn();
      if (isPromiseLike(result)) {
        return Promise.resolve(result).finally(release);
      }
      release();
      return result;
    } catch (exc) {
      release();
      throw exc;
    }
  }

  private _pullResultCount(result: unknown): number {
    if (Array.isArray(result)) return result.length;
    if (!isJsonObject(result as JsonValue | object | undefined)) return 0;
    const obj = result as Record<string, unknown>;
    const rawCount = Number(obj.raw_count ?? 0);
    if (Number.isFinite(rawCount) && rawCount > 0) return rawCount;
    if (Array.isArray(obj.messages)) return obj.messages.length;
    if (Array.isArray(obj.events)) return obj.events.length;
    return 0;
  }

  private _nextPullParams(method: string, params: RpcParams): RpcParams | null {
    const next: RpcParams = { ...params };
    delete next._pull_gate_locked;
    if (method === 'message.pull' || method === 'message.v2.pull') {
      if (!this._aid) return null;
      next.after_seq = this._seqTracker.getContiguousSeq(`p2p:${this._aid}`);
      return next;
    }
    if (method === 'group.pull' || method === 'group.v2.pull') {
      const groupId = normalizeGroupId(String(next.group_id ?? '').trim()) || String(next.group_id ?? '').trim();
      if (!groupId) return null;
      next.group_id = groupId;
      next.after_seq = this._seqTracker.getContiguousSeq(`group:${groupId}`);
      delete next.after_message_seq;
      return next;
    }
    if (method === 'group.pull_events') {
      const groupId = normalizeGroupId(String(next.group_id ?? '').trim()) || String(next.group_id ?? '').trim();
      if (!groupId) return null;
      next.group_id = groupId;
      next.after_event_seq = this._seqTracker.getContiguousSeq(`group_event:${groupId}`);
      return next;
    }
    return null;
  }

  private _pullRequestAfter(method: string, params: RpcParams): number {
    if (method === 'message.pull' || method === 'message.v2.pull') return Number(params.after_seq ?? 0) || 0;
    if (method === 'group.pull' || method === 'group.v2.pull') return Number(params.after_seq ?? params.after_message_seq ?? 0) || 0;
    if (method === 'group.pull_events') return Number(params.after_event_seq ?? 0) || 0;
    return 0;
  }

  private _pullRetentionFloor(result: JsonObject, topLevelKey: string, cursorKey: string): number {
    const values: number[] = [Number(result[topLevelKey] ?? 0)];
    const cursor = isJsonObject(result.cursor as JsonValue | object | null | undefined) ? result.cursor as JsonObject : null;
    if (cursor) {
      values.push(Number(cursor[cursorKey] ?? 0));
      values.push(Number(cursor.retention_floor_seq ?? 0));
    }
    return Math.max(0, ...values.filter((value) => Number.isFinite(value)));
  }

  private _schedulePullFollowup(method: string, params: RpcParams, result: unknown): void {
    if (method === 'message.pull') method = 'message.v2.pull';
    else if (method === 'group.pull') method = 'group.v2.pull';
    if (this._pullResultCount(result) <= 0) return;
    const next = this._nextPullParams(method, params);
    if (!next) return;
    if (this._pullRequestAfter(method, next) <= this._pullRequestAfter(method, params)) return;
    void (async () => {
      try {
        await this._withBackgroundRpc(async () => {
          if (method === 'message.pull' || method === 'message.v2.pull') {
            await this._pullV2(Number(next.after_seq ?? 0) || 0, Number(next.limit ?? 50) || 50);
            return;
          }
          if (method === 'group.pull' || method === 'group.v2.pull') {
            const groupId = String(next.group_id ?? '').trim();
            if (!groupId) return;
            await this._pullGroupV2(groupId, Number(next.after_seq ?? next.after_message_seq ?? 0) || 0, Number(next.limit ?? 50) || 50);
            return;
          }
          await this.call(method, next);
        });
      } catch (exc) {
        this._clientLog.debug(`pull follow-up skipped/failed: method=${method} err=${formatCaughtError(exc)}`);
      }
    })();
  }

  private async _withBackgroundRpc<T>(operation: () => Promise<T> | T): Promise<T> {
    this._backgroundRpcDepth += 1;
    try {
      return await operation();
    } finally {
      this._backgroundRpcDepth = Math.max(0, this._backgroundRpcDepth - 1);
    }
  }

  private async _runPullSerialized<T>(key: string, operation: () => Promise<T> | T): Promise<T> {
    if (key && this._isPullResponseProcessing(key)) {
      this._clientLog.debug(`pull skipped while processing pull response: key=${key}`);
      return [] as unknown as T;
    }
    let token = this._tryAcquirePullGate(key);
    if (token === null) {
      // 显式 pull 可能撞上 push/gap-fill 的后台 pull。这里不并行发第二个 pull，
      // 也不把后台 in-flight 暴露成业务错误；短等待 gate 释放后再进入连接级 RPC queue。
      const deadline = Date.now() + AUNClient.PULL_GATE_STALE_MS + 100;
      while (token === null && Date.now() <= deadline) {
        await this._sleep(25);
        token = this._tryAcquirePullGate(key);
      }
      if (token === null) {
        throw new StateError(`pull already in-flight for ${key}`);
      }
    }
    try {
      return await this._withBackgroundRpc(operation);
    } finally {
      this._releasePullGate(key, token);
    }
  }

  private async _tryRunBackgroundPull(
    key: string,
    operation: () => Promise<number> | number,
    followupOnMessages = false,
    onBusy?: () => void,
  ): Promise<boolean> {
    if (key && this._isPullResponseProcessing(key)) {
      onBusy?.();
      return false;
    }
    const token = this._tryAcquirePullGate(key);
    if (token === null) {
      onBusy?.();
      return false;
    }
    let count = 0;
    try {
      count = await this._withBackgroundRpc(operation);
    } finally {
      this._releasePullGate(key, token);
    }
    if (followupOnMessages && count > 0) {
      // 后台续拉是 fire-and-forget；关闭连接时 transport 会拒绝排队 RPC，
      // 这里必须本地收口，避免测试/宿主进程看到未处理的 Promise rejection。
      void this._tryRunBackgroundPull(key, operation, true).catch((exc) => {
        this._clientLog.debug(`background pull follow-up skipped/failed: key=${key} err=${formatCaughtError(exc)}`);
      });
    }
    return true;
  }

  private async _drainOrderedMessages(ns: string, beforeSeq?: number, pullResponse = false): Promise<void> {
    const queue = this._pendingOrderedMsgs.get(ns);
    if (!queue || queue.size === 0) return;
    while (true) {
      const contig = this._seqTracker.getContiguousSeq(ns);
      const ready = [...queue.keys()]
        .filter((seq) => seq <= contig && (beforeSeq === undefined || seq < beforeSeq))
        .sort((a, b) => a - b);
      let seq: number | undefined = ready[0];
      if (seq === undefined) {
        const nextSeq = contig + 1;
        if (beforeSeq !== undefined && nextSeq >= beforeSeq) break;
        if (!queue.has(nextSeq)) break;
        seq = nextSeq;
      }
      const item = queue.get(seq);
      queue.delete(seq);
      if (!item) continue;
      if (this._pushedSeqs.get(ns)?.has(seq)) {
        this._clientLog.debug(`publish ordered drain skipped duplicate: ns=${ns}, seq=${seq}, event=${item.event}`);
        this._markOrderedSeqDelivered(ns, seq);
        continue;
      }
      if (pullResponse) {
        const published = this._withPullResponseProcessing(ns, () => this._publishAppEvent(item.event, item.payload, 'ordered-drain'));
        if (isPromiseLike(published)) await published;
      } else {
        const published = this._publishAppEvent(item.event, item.payload, 'ordered-drain');
        if (isPromiseLike(published)) await published;
      }
      this._markPublishedSeq(ns, seq);
      this._markOrderedSeqDelivered(ns, seq);
      this._clientLog.debug(`publish ordered drain delivered: ns=${ns}, seq=${seq}, event=${item.event}`);
    }
    if (queue.size === 0) this._pendingOrderedMsgs.delete(ns);
  }

  private async _publishOrderedMessage(event: string, ns: string, seq: unknown, payload: EventPayload): Promise<boolean> {
    const seqNum = Number(seq);
    if (!Number.isFinite(seqNum) || !Number.isInteger(seqNum) || seqNum <= 0) {
      this._clientLog.debug(`publish ordered direct(no-seq): event=${event}, ns=${ns || '<none>'}, seq=${String(seq)}`);
      const published = this._publishAppEvent(event, payload, 'ordered');
      if (isPromiseLike(published)) await published;
      return true;
    }
    if (this._pushedSeqs.get(ns)?.has(seqNum)) {
      this._clientLog.debug(`publish ordered skipped duplicate: event=${event}, ns=${ns}, seq=${seqNum}`);
      const queue = this._pendingOrderedMsgs.get(ns);
      queue?.delete(seqNum);
      if (queue && queue.size === 0) this._pendingOrderedMsgs.delete(ns);
      return false;
    }

    const contig = this._seqTracker.getContiguousSeq(ns);
    if (seqNum <= contig) {
      this._clientLog.debug(`publish ordered stale covered: event=${event}, ns=${ns}, seq=${seqNum}, contiguous=${contig}`);
      const queue = this._pendingOrderedMsgs.get(ns);
      queue?.delete(seqNum);
      if (queue && queue.size === 0) this._pendingOrderedMsgs.delete(ns);
      return false;
    }
    if (seqNum !== contig + 1) {
      this._clientLog.debug(`publish ordered enqueue(gap): event=${event}, ns=${ns}, seq=${seqNum}, contiguous=${contig}`);
      this._enqueueOrderedMessage(ns, event, seqNum, payload);
      return false;
    }

    await this._drainOrderedMessages(ns, seqNum);
    if (this._pushedSeqs.get(ns)?.has(seqNum)) {
      this._clientLog.debug(`publish ordered skipped after-drain duplicate: event=${event}, ns=${ns}, seq=${seqNum}`);
      return false;
    }
    const queue = this._pendingOrderedMsgs.get(ns);
    queue?.delete(seqNum);
    if (queue && queue.size === 0) this._pendingOrderedMsgs.delete(ns);
    const published = this._publishAppEvent(event, payload, 'ordered');
    if (isPromiseLike(published)) await published;
    this._markPublishedSeq(ns, seqNum);
    this._markOrderedSeqDelivered(ns, seqNum);
    this._clientLog.debug(`publish ordered delivered: event=${event}, ns=${ns}, seq=${seqNum}`);
    await this._drainOrderedMessages(ns);
    return true;
  }

  private async _publishPulledMessage(event: string, ns: string, seq: unknown, payload: EventPayload): Promise<boolean> {
    // Pull/gap-fill 批次是服务端对 after_seq 的可用结果集，可能跨过永久空洞。
    // 这里只能做 namespace+seq 去重并按返回顺序发布，不能套用 push 路径的
    // seq == contiguous_seq + 1 门控，否则会把空洞后的可用消息错误卡住。
    const seqNum = Number(seq);
    if (!Number.isFinite(seqNum) || !Number.isInteger(seqNum) || seqNum <= 0 || !ns) {
      this._clientLog.debug(`publish pulled direct(no-seq): event=${event}, ns=${ns || '<none>'}, seq=${String(seq)}`);
      const published = this._withPullResponseProcessing(ns, () => this._publishAppEvent(event, payload, 'pull'));
      if (isPromiseLike(published)) await published;
      return true;
    }
    const queue = this._pendingOrderedMsgs.get(ns);
    if (this._pushedSeqs.get(ns)?.has(seqNum)) {
      this._clientLog.debug(`publish pulled skipped duplicate: event=${event}, ns=${ns}, seq=${seqNum}`);
      queue?.delete(seqNum);
      if (queue && queue.size === 0) this._pendingOrderedMsgs.delete(ns);
      return false;
    }
    queue?.delete(seqNum);
    if (queue && queue.size === 0) this._pendingOrderedMsgs.delete(ns);
    const published = this._withPullResponseProcessing(ns, () => this._publishAppEvent(event, payload, 'pull'));
    if (isPromiseLike(published)) await published;
    this._markPublishedSeq(ns, seqNum);
    this._markPulledSeqDelivered(ns, seqNum);
    await this._drainOrderedMessages(ns, undefined, true);
    this._clientLog.debug(`publish pulled delivered: event=${event}, ns=${ns}, seq=${seqNum}`);
    return true;
  }

  private _markPulledSeqDelivered(ns: string, seq: unknown): boolean {
    // Pull 批次是 after_seq 之后服务端当前可用的结果集，可能跨过永久空洞。
    // 这里仅在应用层发布返回后推进已交付游标，不能改成 push 的相邻 seq 门控。
    const seqNum = Number(seq);
    if (!ns || !Number.isFinite(seqNum) || !Number.isInteger(seqNum) || seqNum <= 0) return false;
    const before = this._seqTracker.getContiguousSeq(ns);
    this._seqTracker.forceContiguousSeq(ns, seqNum);
    return this._seqTracker.getContiguousSeq(ns) !== before;
  }

  private _markOrderedSeqDelivered(ns: string, seq: number): boolean {
    if (!ns || !Number.isFinite(seq) || !Number.isInteger(seq) || seq <= 0) return false;
    const before = this._seqTracker.getContiguousSeq(ns);
    this._seqTracker.onMessageSeq(ns, seq);
    return this._seqTracker.getContiguousSeq(ns) !== before;
  }

  /** 后台补齐群事件空洞 */
  private async _fillGroupEventGap(groupId: string): Promise<void> {
    groupId = normalizeGroupId(groupId) || String(groupId ?? '').trim();
    if (!groupId) return;
    const ns = `group_event:${groupId}`;
    const afterSeq = this._seqTracker.getContiguousSeq(ns);
    // 去重：同一 (group_evt:id:after_seq) 只补一次
    const dedupKey = `group_evt:${groupId}:${afterSeq}`;
    if (this._gapFillDone.has(dedupKey)) return;
    const token = this._tryAcquirePullGate(ns);
    if (token === null) {
      this._clientLog.debug(`group event gap fill skipped: pull in-flight group=${groupId}`);
      return;
    }
    this._gapFillDone.set(dedupKey, Date.now());
    let filled = 0;
    try {
      let nextAfterSeq = afterSeq;
      const maxPages = 100;
      let pageCount = 0;
      while (pageCount < maxPages) {
        pageCount += 1;
        this._clientLog.debug(`group event gap fill start: group=${groupId}, after_seq=${nextAfterSeq}`);
        const result = await this.call('group.pull_events', {
          group_id: groupId,
          after_event_seq: nextAfterSeq,
          device_id: this._deviceId,
          limit: 50,
          _pull_gate_locked: true,
        });
        if (!isJsonObject(result)) return;
        const events = result.events;
        if (!Array.isArray(events)) return;
        const pageContigBefore = this._seqTracker.getContiguousSeq(ns);
        const eventObjects = events.filter(isJsonObject);
        const retentionFloor = this._pullRetentionFloor(result as JsonObject, 'retention_floor_event_seq', 'retention_floor_event_seq');
        if (retentionFloor > 0) {
          const contigBeforeFloor = this._seqTracker.getContiguousSeq(ns);
          if (contigBeforeFloor < retentionFloor) {
            this._clientLog.info(`group.pull_events retention-floor advance: ns=${ns} contiguous=${contigBeforeFloor} -> retention_floor=${retentionFloor}`);
            this._seqTracker.forceContiguousSeq(ns, retentionFloor);
          }
        }
        const eventSeqs: number[] = [];
        for (const evt of eventObjects) {
          const eventSeq = Number(evt.event_seq ?? 0);
          if (Number.isFinite(eventSeq) && eventSeq > 0) eventSeqs.push(eventSeq);
          evt._from_gap_fill = true;
          const et = String(evt.event_type ?? '');
          // 消息事件由 _fillGroupGap 负责，事件补洞不重复投递
          if (et !== 'group.message_created') {
            // 验签：有 client_signature 就验（与实时事件路径对齐）
            const cs = evt.client_signature;
            if (cs && typeof cs === 'object') {
              if (this._shouldSkipEventSignature(evt)) {
                delete evt.client_signature;
              } else {
                evt._verified = await this._verifyEventSignatureAsync(evt, cs as JsonObject);
              }
            }
            // group.changed 或缺失/其他 → 发布到 group.changed（向后兼容）
            await this._dispatcher.publish('group.changed', evt);
          }
          if (Number.isFinite(eventSeq) && eventSeq > 0) {
            this._markPulledSeqDelivered(ns, eventSeq);
          }
          filled += 1;
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
          }, undefined, undefined, true).catch((e) => { this._clientLog.debug(`group event auto-ack failed: group=${groupId} ${formatCaughtError(e)}`); });
        }
        // pull_events 与其它 pull 一样：一次后台任务只消费一个批次。
        // 非空批次返回后由 pull gate 的 fire-and-forget follow-up 重新排队，直到空批停止。
        break;
      }
      if (pageCount >= maxPages) {
        this._clientLog.warn(`group event gap fill reached max_pages=${maxPages} group=${groupId} after_seq=${nextAfterSeq}`);
      }
      this._clientLog.debug(`group event gap fill done: group=${groupId}, after_seq=${afterSeq}, filled=${filled}`);
    } catch (exc) {
      this._clientLog.warn(`group event gap fill failed: ${formatCaughtError(exc)}`);
    } finally {
      this._gapFillDone.delete(dedupKey);
      this._releasePullGate(ns, token);
      if (filled > 0 && this._seqTracker.getContiguousSeq(ns) > afterSeq) {
        void this._fillGroupEventGap(groupId);
      }
    }
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
    try {
    if (isJsonObject(data)) {
      const d = data;
      const groupId = String(d.group_id ?? '');
      const action = String(d.action ?? '');
      this._clientLog.debug(`_onRawGroupChanged enter: group_id=${groupId}, action=${action}, event_seq=${String(d.event_seq ?? '')}`);
      // 验签：有 client_signature 就验，没有默认安全（H20: 严格 boolean）
      const cs = d.client_signature;
      if (cs && isJsonObject(cs)) {
        if (this._shouldSkipEventSignature(d)) {
          delete d.client_signature;
        } else {
          d._verified = await this._verifyEventSignatureAsync(d, cs);
        }
      }
      await this._dispatcher.publish('group.changed', d);

      // V2-only：成员/设备变化会影响 group.v2.bootstrap 的设备集与 state commitment。
      if (groupId) {
        this._v2BootstrapCache.delete(`group:${groupId}`);
      }
      const membershipActions = new Set([
        'member_added', 'member_left', 'member_removed', 'role_changed',
        'owner_transferred', 'joined', 'join_approved', 'invite_code_used',
      ]);
      if (groupId && this._v2Session && (action === 'upsert' || membershipActions.has(action))) {
        this._safeAsync(this._v2AutoProposeState(groupId, { leaderDelay: true }));
      }

      // Group SPK 编排：成员变更触发注册/轮换
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
              this._clientLog.debug(`group SPK registration failed (non-fatal): group=${groupId} action=${action} err=${formatCaughtError(exc)}`);
            });
          } else {
            this._v2Session.rotateGroupSPK?.(groupId, callFn)?.catch(exc => {
              this._clientLog.debug(`group SPK rotation failed (non-fatal): group=${groupId} action=${action} err=${formatCaughtError(exc)}`);
            });
          }
        }
      }

      // event_seq 空洞检测：持久化后的 group.changed 会携带 event_seq。
      // 用 onMessageSeq 返回值决定是否补拉，与 P2P / group.message 路径对齐。
      let needPull = false;
      const rawEventSeq = d.event_seq;
      if (rawEventSeq != null && groupId) {
        const es = Number(rawEventSeq);
        if (Number.isFinite(es) && es > 0) {
          needPull = this._seqTracker.onMessageSeq(`group_event:${groupId}`, es);
        }
        // ISSUE-TS-002: 群事件推送路径 ack + 持久化，与 P2P/群消息路径对齐
        this._saveSeqTrackerState();
        const contig = this._seqTracker.getContiguousSeq(`group_event:${groupId}`);
        if (contig > 0) {
          this._transport.call('group.ack_events', {
            group_id: groupId,
            event_seq: contig,
            device_id: this._deviceId,
            slot_id: this._slotId,
          }, undefined, undefined, true).catch((e) => { this._clientLog.debug(`group event push auto-ack failed: group=${groupId} ${formatCaughtError(e)}`); });
        }
      }

      // 仅在真实 event gap 时才触发补拉（补洞回来的事件不再触发新补洞）
      if (needPull && groupId && !d._from_gap_fill) {
        this._fillGroupEventGap(groupId).catch(exc => this._clientLog.warn(`background gap fill trigger failed: ${formatCaughtError(exc)}`));
      }

      // 群组解散 → 清理本地 epoch key、seq_tracker、补洞去重缓存
      if (d.action === 'dissolved') {
        if (groupId) {
          this._cleanupDissolvedGroup(groupId);
        }
      }
    } else {
      // data 非对象也透传给用户（兼容旧版）
      await this._dispatcher.publish('group.changed', data);
    }
    this._clientLog.debug(`_onRawGroupChanged exit: elapsed=${Date.now() - tStart}ms`);
    } catch (err) {
      this._clientLog.debug(`_onRawGroupChanged exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /**
   * 处理 event/group.state_committed：验证 state_hash 链并更新本地存储。
   * 当链断裂时回源 group.get_state，并对回源结果做本地 hash 重算验证。
   */
  private async _onGroupStateCommitted(data: EventPayload): Promise<void> {
    const tStart = Date.now();
    if (!isJsonObject(data)) {
      this._clientLog.debug(`_onGroupStateCommitted exit: elapsed=${Date.now() - tStart}ms (non-object payload)`);
      return;
    }
    const d = data;
    const groupId = String(d.group_id ?? '').trim();
    if (!groupId) {
      this._clientLog.debug(`_onGroupStateCommitted exit: elapsed=${Date.now() - tStart}ms (no group_id)`);
      return;
    }
    this._clientLog.debug(`_onGroupStateCommitted enter: group_id=${groupId}, state_version=${String(d.state_version ?? '')}`);
    try {
    // 提交者签名验证（兼容旧版：无签名时继续）
    const cs = d.client_signature;
    if (cs && isJsonObject(cs)) {
      if (this._shouldSkipEventSignature(d)) {
        delete d.client_signature;
      } else {
        const verified = await this._verifyEventSignatureAsync(d, cs);
        if (verified === false) {
          this._clientLog.warn(`state_committed committer signature verification failed group=${groupId}`);
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
    const loadFn = this._keystore.loadGroupState;
    const localState = loadFn ? loadFn.call(this._keystore, groupId) : null;
    if (localState && localState.state_hash && localState.state_hash !== prevStateHash) {
      this._clientLog.warn(`state_hash chain discontinuous group=${groupId} local_sv=${localState.state_version} event_sv=${stateVersion}`);
      // 回源同步
      try {
        const serverState = await this._transport.call('group.get_state', { group_id: groupId });
        if (serverState && isJsonObject(serverState) && 'state_version' in serverState) {
          const sv = Number(serverState.state_version ?? 0);
          const sHash = String(serverState.state_hash ?? '');
          const sEpoch = Number(serverState.key_epoch ?? 0);
          const sMembersJson = String(serverState.membership_snapshot ?? '');
          const sPolicyJson = String(serverState.policy_snapshot ?? '');
          const sPrev = String(serverState.prev_state_hash ?? '');
          // 回源也做 hash 验证
          if (sMembersJson && sHash) {
            const sMembers: Array<{ aid: string; role: string }> = sMembersJson ? JSON.parse(sMembersJson) : [];
            const sPolicy: Record<string, unknown> = sPolicyJson ? JSON.parse(sPolicyJson) : {};
            const computed = computeStateHash({
              groupId, stateVersion: sv, keyEpoch: sEpoch,
              members: sMembers, policy: sPolicy, prevStateHash: sPrev,
            });
            if (computed !== sHash) {
              this._clientLog.warn(`backfill state_hash verification failed group=${groupId} sv=${sv} expected=${sHash} got=${computed}`);
              return;
            }
          }
          const saveFn = this._keystore.saveGroupState;
          if (saveFn) {
            saveFn.call(this._keystore, groupId, sv, sHash, sEpoch, sMembersJson || membershipSnapshot, sPolicyJson || policySnapshot);
          }
        }
      } catch (exc) {
        this._clientLog.warn(`state backfill failed group=${groupId}: ${formatCaughtError(exc)}`);
      }
      return;
    }

    // 2. 本地重算验证
    const members: Array<{ aid: string; role: string }> = membershipSnapshot ? JSON.parse(membershipSnapshot) : [];
    const policy: Record<string, unknown> = policySnapshot ? JSON.parse(policySnapshot) : {};
    const computed = computeStateHash({
      groupId, stateVersion, keyEpoch,
      members, policy, prevStateHash,
    });
    if (computed !== stateHash) {
      this._clientLog.warn(`state_hash recompute mismatch group=${groupId} sv=${stateVersion} expected=${stateHash} got=${computed}`);
      return;
    }

    // 3. 更新本地存储
    const saveFn = this._keystore.saveGroupState;
    if (saveFn) {
      saveFn.call(this._keystore, groupId, stateVersion, stateHash, keyEpoch, membershipSnapshot, policySnapshot);
    }
    this._clientLog.debug(`_onGroupStateCommitted exit: elapsed=${Date.now() - tStart}ms group=${groupId}`);
    } catch (err) {
      this._clientLog.debug(`_onGroupStateCommitted exit (error): elapsed=${Date.now() - tStart}ms group=${groupId} err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 群组解散后清理本地 V2 缓存、seq_tracker 和补洞去重缓存。 */
  private _cleanupDissolvedGroup(groupId: string): void {
    this._v2BootstrapCache.delete(`group:${groupId}`);
    this._v2GroupSecurityLevels.delete(groupId);
    this._v2StateChains.delete(groupId);
    this._seqTracker.removeNamespace(`group:${groupId}`);
    this._seqTracker.removeNamespace(`group_event:${groupId}`);
    this._saveSeqTrackerState();

    for (const key of this._gapFillDone.keys()) {
      if (key.includes(groupId)) {
        this._gapFillDone.delete(key);
      }
    }

    this._pushedSeqs.delete(`group:${groupId}`);
    this._pushedSeqs.delete(`group_event:${groupId}`);
    this._pendingOrderedMsgs.delete(`group:${groupId}`);

    this._clientLog.info(`cleaned up disbanded group ${groupId} local state`);
  }

  /** 同步验签群事件 client_signature。返回 true/false/"pending"。 */
  /**
   * H20 修复：原来返回 `string | boolean` 的三态；`_verified = 'pending'` 是 truthy
   * 字符串，业务写 `if (event._verified)` 会把"证书未到"当成"已验证"。
   * 改为严格 boolean，证书缺失时 await `_fetchPeerCert` 再判定；若仍失败返回 false
   * 并触发 `signature_pending` 事件让上层感知。
   */
  private async _verifyEventSignatureAsync(event: JsonObject, cs: JsonObject): Promise<boolean> {
    try {
      const sigAid = String(cs.aid ?? '');
      const method = String(cs._method ?? '');
      const expectedFP = String(cs.cert_fingerprint ?? '').trim().toLowerCase();
      if (!sigAid || !method) return false;

      // 先查缓存；缺失则 await 拉取，避免 truthy string 歧义
      let certPem = '';
      const cached = this._certCache.get(AUNClient._certCacheKey(sigAid, expectedFP || undefined));
      if (cached && cached.certPem) {
        certPem = cached.certPem;
      } else {
        try {
          certPem = await this._fetchPeerCert(sigAid, expectedFP || undefined);
        } catch {
          this._dispatcher.publish('signature_pending', { aid: sigAid, method }).catch(() => {});
          return false;
        }
      }

      const certObj = new crypto.X509Certificate(certPem);
      if (expectedFP) {
        const actualFP = 'sha256:' + certObj.fingerprint256.replace(/:/g, '').toLowerCase();
        if (actualFP !== expectedFP) {
          this._clientLog.warn(`signature verification failed: cert fingerprint mismatch aid=${sigAid}`);
          return false;
        }
      }
      const paramsHash = String(cs.params_hash ?? '');
      const timestamp = String(cs.timestamp ?? '');
      const signData = Buffer.from(`${method}|${sigAid}|${timestamp}|${paramsHash}`, 'utf-8');
      const sigB64 = String(cs.signature ?? '');
      const pubKey = certObj.publicKey;
      const ok = crypto.verify('SHA256', signData, pubKey, Buffer.from(sigB64, 'base64'));
      if (!ok) {
        this._clientLog.warn(`group event signature verification failed aid=${sigAid} method=${method}`);
        // P1-16: 签名失败统一发布事件
        this._dispatcher.publish('signature.verification_failed', {
          aid: sigAid, method, error: 'ECDSA verification failed',
        }).catch(() => {});
      }
      return ok;
    } catch (exc) {
      this._clientLog.warn(`group event signature verification error: ${formatCaughtError(exc)}`);
      // P1-16: 签名失败统一发布事件
      this._dispatcher.publish('signature.verification_failed', {
        aid: String(cs.aid ?? ''), method: String(cs._method ?? ''),
        error: formatCaughtError(exc),
      }).catch(() => {});
      return false;
    }
  }

  private async _validateAndCachePeerCert(opts: {
    aid: string;
    certPem: string;
    certFingerprint?: string;
    caChainPems?: string[];
    source?: string;
  }): Promise<string> {
    const aid = String(opts.aid ?? '').trim();
    const certPem = String(opts.certPem ?? '').trim();
    const certFingerprint = String(opts.certFingerprint ?? '').trim() || undefined;
    if (!aid) throw new ValidationError('peer aid is required for cert validation');
    if (!certPem) throw new ValidationError(`peer cert is empty for ${aid}`);

    const gatewayUrl = this._gatewayUrl;
    if (!gatewayUrl) {
      throw new ValidationError('gateway url unavailable for e2ee cert validation');
    }
    const peerGatewayUrl = AUNClient._resolvePeerGatewayUrl(gatewayUrl, aid);
    const x509Cert = new crypto.X509Certificate(certPem);

    // H7: 严格校验指纹（DER SHA-256 或 SPKI SHA-256 任一匹配即可）
    if (certFingerprint) {
      const expectedFP = certFingerprint.toLowerCase();
      if (!expectedFP.startsWith('sha256:')) {
        throw new ValidationError(
          `unsupported cert_fingerprint format for ${aid}: ${expectedFP.slice(0, 24)}`,
        );
      }
      const expectedHex = expectedFP.slice('sha256:'.length);
      const derHex = x509Cert.fingerprint256.replace(/:/g, '').toLowerCase();
      let spkiHex = '';
      try {
        const spkiDer = x509Cert.publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
        spkiHex = crypto.createHash('sha256').update(spkiDer).digest('hex');
      } catch {
        spkiHex = '';
      }
      if (expectedHex !== derHex && (!spkiHex || expectedHex !== spkiHex)) {
        throw new ValidationError(
          `peer cert fingerprint mismatch for ${aid}: expected=${expectedFP.slice(0, 24)}...`,
        );
      }
    }

    let cachedBootstrapChain = false;
    const caChainPems = opts.caChainPems ?? [];
    if (caChainPems.length > 0) {
      try {
        this._auth.cacheGatewayCaChain(peerGatewayUrl, caChainPems, aid);
        cachedBootstrapChain = true;
      } catch (exc) {
        this._clientLog.debug(`bootstrap CA chain cache skipped: peer=${aid}, source=${opts.source ?? 'unknown'}, err=${formatCaughtError(exc)}`);
      }
    }

    try {
      await this._auth.verifyPeerCertificate(peerGatewayUrl, certPem, aid);
    } catch (exc) {
      if (cachedBootstrapChain) {
        this._auth.discardGatewayCaChain(peerGatewayUrl, aid);
      }
      throw new ValidationError(
        `peer cert verification failed for ${aid}: ${exc instanceof Error ? exc.message : String(exc)}`,
      );
    }

    const nowSec = Date.now() / 1000;
    const entry: CachedPeerCert = {
      certPem,
      validatedAt: nowSec,
      refreshAfter: nowSec + PEER_CERT_CACHE_TTL,
    };
    const cacheKey = AUNClient._certCacheKey(aid, certFingerprint);
    this._certCache.set(cacheKey, entry);
    const bareKey = AUNClient._certCacheKey(aid);
    if (bareKey !== cacheKey) this._certCache.set(bareKey, entry);
    if (!certFingerprint) {
      const actualFp = `sha256:${x509Cert.fingerprint256.replace(/:/g, '').toLowerCase()}`;
      this._certCache.set(AUNClient._certCacheKey(aid, actualFp), entry);
    }

    try {
      // peer 证书只存版本目录，不覆盖 cert.pem
      this._keystore.saveCert(aid, certPem, certFingerprint, { makeActive: false });
    } catch (exc) {
      this._clientLog.error(`failed to write cert to keystore (aid=${aid}, fp=${certFingerprint ?? ''}): ${formatCaughtError(exc)}`, exc instanceof Error ? exc : undefined);
    }

    return certPem;
  }

  /** 获取对方证书（带缓存 + 完整 PKI 验证），跨域时自动路由到 peer 所在域。 */
  private async _fetchPeerCert(aid: string, certFingerprint?: string, timeoutMs = 30_000): Promise<string> {
    const tStart = Date.now();
    this._clientLog.debug(`_fetchPeerCert enter: aid=${aid}, fp=${certFingerprint ?? ''}`);
    try {
      const cacheKey = AUNClient._certCacheKey(aid, certFingerprint);
      const cached = this._certCache.get(cacheKey);
      const now = Date.now() / 1000;
      if (cached && now < cached.refreshAfter) {
        this._clientLog.debug(`_fetchPeerCert exit: elapsed=${Date.now() - tStart}ms aid=${aid} (cache_hit)`);
        return cached.certPem;
      }

      const gatewayUrl = this._gatewayUrl;
      if (!gatewayUrl) {
        throw new ValidationError('gateway url unavailable for e2ee cert fetch');
      }
      const peerGatewayUrl = AUNClient._resolvePeerGatewayUrl(gatewayUrl, aid);
      let certPem: string;
      try {
        certPem = await _httpGetText(
          AUNClient._buildCertUrl(peerGatewayUrl, aid, certFingerprint),
          this._configModel.verifySsl,
          timeoutMs,
        );
      } catch (exc) {
        if (!certFingerprint) throw exc;
        certPem = await _httpGetText(
          AUNClient._buildCertUrl(peerGatewayUrl, aid),
          this._configModel.verifySsl,
          timeoutMs,
        );
      }

      const validated = await this._validateAndCachePeerCert({
        aid,
        certPem,
        certFingerprint,
        source: 'fetch',
      });
      this._clientLog.debug(`_fetchPeerCert exit: elapsed=${Date.now() - tStart}ms aid=${aid} (fetched)`);
      return validated;
    } catch (err) {
      this._clientLog.debug(`_fetchPeerCert exit (error): elapsed=${Date.now() - tStart}ms aid=${aid} err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  private _bootstrapCaChain(material: Record<string, unknown>): string[] {
    let raw: unknown;
    for (const key of ['ca_chain', 'ca_chain_pems', 'cert_chain', 'chain']) {
      if (material[key] !== undefined && material[key] !== null) {
        raw = material[key];
        break;
      }
    }
    if (!Array.isArray(raw)) return [];
    const result: string[] = [];
    for (const item of raw) {
      let certType = '';
      let certPem = '';
      if (isJsonObject(item)) {
        certType = String(item.cert_type ?? '').trim().toLowerCase();
        if (certType === 'agent') continue;
        certPem = String(item.cert_pem ?? item.cert ?? '').trim();
      } else {
        certPem = String(item ?? '').trim();
      }
      if (!certPem) continue;
      if (!certType) {
        try {
          if (!new crypto.X509Certificate(certPem).ca) continue;
        } catch {
          continue;
        }
      }
      result.push(certPem);
    }
    return result;
  }

  private async _primeBootstrapPeerCerts(bootstrap: Record<string, unknown>, peerAid: string): Promise<void> {
    const certsRaw = bootstrap.certs as JsonValue | object | null | undefined;
    if (!isJsonObject(certsRaw)) return;
    const materials = certsRaw;
    const expected = new Set<string>();
    const normalizedPeer = String(peerAid ?? '').trim();
    if (normalizedPeer) expected.add(normalizedPeer);
    const audit = Array.isArray(bootstrap.audit_recipients) ? bootstrap.audit_recipients : [];
    for (const dev of audit) {
      if (!isJsonObject(dev)) continue;
      const aid = String(dev.aid ?? '').trim();
      if (aid) expected.add(aid);
    }
    for (const aid of expected) {
      if (aid === this._aid) continue;
      const material = materials[aid];
      if (!isJsonObject(material)) continue;
      const certPem = String(material.cert_pem ?? material.cert ?? '').trim();
      if (!certPem) continue;
      const certFingerprint = String(
        material.cert_fingerprint ?? material.fingerprint ?? material.fp ?? '',
      ).trim() || undefined;
      try {
        await this._validateAndCachePeerCert({
          aid,
          certPem,
          certFingerprint,
          caChainPems: this._bootstrapCaChain(material),
          source: 'bootstrap',
        });
      } catch (exc) {
        this._clientLog.debug(`bootstrap peer cert material ignored: peer=${aid}, err=${formatCaughtError(exc)}`);
      }
    }
  }

  private async _decryptGroupThoughts(result: JsonObject): Promise<JsonObject> {
    this._clientLog.debug(`group.thought.get decrypt enter: found=${String(result.found ?? '')}, group=${String(result.group_id ?? '')}, sender=${String(result.sender_aid ?? '')}`);
    if (!result.found) {
      this._clientLog.debug('group.thought.get decrypt exit: not found');
      return { ...result, thoughts: [] as JsonValue[] };
    }
    const items = Array.isArray(result.thoughts) ? result.thoughts.filter(isJsonObject) : [];
    if (items.length === 0) {
      this._clientLog.debug('group.thought.get decrypt exit: empty thoughts');
      return { ...result, thoughts: [] as JsonValue[] };
    }
    const groupId = String(result.group_id ?? '');
    const senderAid = String(result.sender_aid ?? '');
    const thoughts: JsonObject[] = [];
    for (const item of items) {
      const payload = isJsonObject(item.payload) ? item.payload : null;
      const thoughtId = String(item.thought_id ?? item.message_id ?? '');
      const fromAid = String(item.from ?? item.sender_aid ?? senderAid);
      this._logMessageDebug('thought-get-raw', 'group.thought.get', 'group.thought.get', item, {
        extra: { group_id: groupId, thought_id: thoughtId, from: fromAid },
      });
      let decryptFailed = false;
      let decryptedPayload: JsonValue | object = payload ?? {};
      let e2ee: JsonValue | undefined;
      if (payload?.type === 'e2ee.group_encrypted' && String(payload.version ?? '') === 'v2') {
        e2ee = this._v2E2eeMeta(payload);
        const plain = await this._decryptV2EnvelopeForThought({ envelope: payload, fromAid });
        if (plain === null) {
          decryptFailed = true;
          this._clientLog.debug(`group.thought.get decrypt returned null: group=${groupId}, thought_id=${thoughtId}, from=${fromAid}`);
        } else {
          decryptedPayload = plain;
          this._logMessageDebug('thought-decrypt-ok', 'group.thought.get', 'group.thought.get', {
            group_id: groupId,
            thought_id: thoughtId,
            from: fromAid,
            payload: plain,
          });
        }
      } else if (payload?.type === 'e2ee.group_encrypted') {
        decryptFailed = true;
        this._clientLog.debug(`group.thought.get unsupported encrypted payload: group=${groupId}, thought_id=${thoughtId}, type=${String(payload.type ?? '')}, version=${String(payload.version ?? '')}`);
      }
      const thought: JsonObject = {
        thought_id: thoughtId,
        message_id: thoughtId,
        payload: decryptFailed ? (payload ?? {}) : decryptedPayload as JsonValue,
        created_at: item.created_at,
      };
      if (e2ee !== undefined) {
        thought.e2ee = e2ee;
        if (isJsonObject(e2ee)) this._attachV2EnvelopeMetadata(thought, e2ee);
      }
      if (decryptFailed) thought.decrypt_failed = true;
      if ('context' in item) thought.context = item.context;
      this._logMessageDebug(decryptFailed ? 'thought-decrypt-fail' : 'thought-result', 'group.thought.get', 'group.thought.get', thought, {
        extra: { group_id: groupId, thought_id: thoughtId },
      });
      thoughts.push(thought);
    }
    this._clientLog.debug(`group.thought.get decrypt exit: group=${groupId}, total=${items.length}, returned=${thoughts.length}`);
    return { ...result, thoughts };
  }

  private async _decryptMessageThoughts(result: JsonObject): Promise<JsonObject> {
    this._clientLog.debug(`message.thought.get decrypt enter: found=${String(result.found ?? '')}, peer=${String(result.peer_aid ?? '')}, sender=${String(result.sender_aid ?? '')}`);
    if (!result.found) {
      this._clientLog.debug('message.thought.get decrypt exit: not found');
      return { ...result, thoughts: [] as JsonValue[] };
    }
    const items = Array.isArray(result.thoughts) ? result.thoughts.filter(isJsonObject) : [];
    if (items.length === 0) {
      this._clientLog.debug('message.thought.get decrypt exit: empty thoughts');
      return { ...result, thoughts: [] as JsonValue[] };
    }
    const senderAid = String(result.sender_aid ?? '');
    const peerAid = String(result.peer_aid ?? '');
    const thoughts: JsonObject[] = [];
    for (const item of items) {
      const payload = isJsonObject(item.payload) ? item.payload : null;
      const thoughtId = String(item.thought_id ?? item.message_id ?? '');
      const fromAid = String(item.from ?? senderAid);
      const toAid = String(item.to ?? peerAid);
      this._logMessageDebug('thought-get-raw', 'message.thought.get', 'message.thought.get', item, {
        extra: { thought_id: thoughtId, from: fromAid, to: toAid },
      });
      let decryptFailed = false;
      let decryptedPayload: JsonValue | object = payload ?? {};
      let e2ee: JsonValue | undefined;
      if (payload?.type === 'e2ee.p2p_encrypted' && String(payload.version ?? '') === 'v2') {
        e2ee = this._v2E2eeMeta(payload);
        const plain = await this._decryptV2EnvelopeForThought({ envelope: payload, fromAid });
        if (plain === null) {
          decryptFailed = true;
          this._clientLog.debug(`message.thought.get decrypt returned null: thought_id=${thoughtId}, from=${fromAid}, to=${toAid}`);
        } else {
          decryptedPayload = plain;
          this._logMessageDebug('thought-decrypt-ok', 'message.thought.get', 'message.thought.get', {
            thought_id: thoughtId,
            from: fromAid,
            to: toAid,
            payload: plain,
          });
        }
      } else if (payload?.type === 'e2ee.encrypted' || payload?.type === 'e2ee.p2p_encrypted') {
        decryptFailed = true;
        this._clientLog.debug(`message.thought.get unsupported encrypted payload: thought_id=${thoughtId}, type=${String(payload.type ?? '')}, version=${String(payload.version ?? '')}`);
      }
      const thought: JsonObject = {
        thought_id: thoughtId,
        message_id: thoughtId,
        from: fromAid,
        to: toAid,
        payload: decryptFailed ? (payload ?? {}) : decryptedPayload as JsonValue,
        created_at: item.created_at,
      };
      if (e2ee !== undefined) {
        thought.e2ee = e2ee;
        if (isJsonObject(e2ee)) this._attachV2EnvelopeMetadata(thought, e2ee);
      }
      if (decryptFailed) thought.decrypt_failed = true;
      if ('context' in item) thought.context = item.context;
      this._logMessageDebug(decryptFailed ? 'thought-decrypt-fail' : 'thought-result', 'message.thought.get', 'message.thought.get', thought, {
        extra: { thought_id: thoughtId },
      });
      thoughts.push(thought);
    }
    this._clientLog.debug(`message.thought.get decrypt exit: total=${items.length}, returned=${thoughts.length}`);
    return { ...result, thoughts };
  }

  /** 从 keystore 恢复 SeqTracker 状态 */  /** 从 keystore 恢复 SeqTracker 状态 */
  private _restoreSeqTrackerState(): void {
    if (!this._aid) return;
    try {
      // 优先从 seq_tracker 表按行读取
      const loadAll = this._keystore.loadAllSeqs;
      if (typeof loadAll === 'function') {
        let state = loadAll.call(this._keystore, this._aid, this._deviceId, this._slotId);
        if (state && Object.keys(state).length > 0) {
          state = this._migrateSeqStateGroupIds(state);
          this._seqTracker.restoreState(state);
          return;
        }
      }
      // fallback: 从旧 instance_state JSON blob 恢复
      const loader = (this._keystore as KeyStore & {
        loadInstanceState?: (aid: string, deviceId: string, slotId?: string) => MetadataRecord | null;
      }).loadInstanceState;
      if (typeof loader === 'function') {
        const instanceState = loader.call(this._keystore, this._aid, this._deviceId, this._slotId);
        if (instanceState && typeof instanceState.seq_tracker_state === 'object') {
          let state = instanceState.seq_tracker_state as Record<string, number>;
          state = this._migrateSeqStateGroupIds(state);
          this._seqTracker.restoreState(state);
        }
      }
    } catch (exc) {
      this._clientLog.warn(`restore SeqTracker state failed: ${formatCaughtError(exc)}`);
      // 通过内部 dispatcher 发布可观测事件，便于上层监控
      this._dispatcher.publish('seq_tracker.persist_error', {
        phase: 'restore',
        aid: this._aid,
        device_id: this._deviceId,
        slot_id: this._slotId,
        error: String(formatCaughtError(exc)),
      }).catch(() => {});
    }
  }

  /**
   * 把 seq_tracker state 里 group_event:/group_msg: 前缀的老/污染 group_id 归一化为 canonical。
   * 冲突取 max。同时落盘删除老 ns、写入新 ns，避免下次启动重复迁移。
   */
  private _migrateSeqStateGroupIds(state: Record<string, number>): Record<string, number> {
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
    this._clientLog.info(`SeqTracker group_id migration: ${Object.keys(renameMap).length} namespaces rewritten`);
    // 落盘
    const saver = this._keystore.saveSeq;
    const deleter = (this._keystore as KeyStore & {
      deleteSeq?: (aid: string, deviceId: string, slotId: string, namespace: string) => void;
    }).deleteSeq;
    if (typeof saver === 'function' && this._aid) {
      for (const [oldNs, newNs] of Object.entries(renameMap)) {
        if (typeof deleter === 'function') {
          try { deleter.call(this._keystore, this._aid, this._deviceId, this._slotId, oldNs); } catch (e) {
            this._clientLog.debug(`delete old seq ns failed: ns=${oldNs} err=${formatCaughtError(e)}`);
          }
        }
        try { saver.call(this._keystore, this._aid, this._deviceId, this._slotId, newNs, newState[newNs]); } catch (e) {
          this._clientLog.debug(`write new seq ns failed: ns=${newNs} err=${formatCaughtError(e)}`);
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
    this._pendingP2pPullUpper.clear();
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
    this._pendingP2pPullUpper.clear();
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
      const saveFn = this._keystore.saveSeq;
      if (typeof saveFn === 'function') {
        for (const [ns, seq] of Object.entries(state)) {
          saveFn.call(this._keystore, this._aid, this._deviceId, this._slotId, ns, seq);
        }
        return;
      }
      // fallback: 旧版 updateInstanceState JSON blob
      const updater = (this._keystore as KeyStore & {
        updateInstanceState?: (
          aid: string,
          deviceId: string,
          slotId: string,
          updater: (metadata: MetadataRecord) => MetadataRecord | void,
        ) => MetadataRecord;
      }).updateInstanceState;
      if (typeof updater === 'function') {
        updater.call(this._keystore, this._aid, this._deviceId, this._slotId, (metadata) => {
          metadata.seq_tracker_state = state;
          return metadata;
        });
      }
    } catch (exc) {
      this._clientLog.warn(`save SeqTracker state failed: ${formatCaughtError(exc)}`);
      // 通过内部 dispatcher 发布可观测事件，便于上层监控
      this._dispatcher.publish('seq_tracker.persist_error', {
        phase: 'save',
        aid: this._aid,
        device_id: this._deviceId,
        slot_id: this._slotId,
        error: String(formatCaughtError(exc)),
      }).catch(() => {});
    }
  }

  private _persistRepairedSeq(ns: string): void {
    if (!this._aid || !ns) return;
    const seq = this._seqTracker.getContiguousSeq(ns);
    try {
      if (seq > 0 && typeof this._keystore.saveSeq === 'function') {
        this._keystore.saveSeq(this._aid, this._deviceId, this._slotId, ns, seq);
        return;
      }
      const deleteSeq = this._keystore.deleteSeq;
      if (seq <= 0 && typeof deleteSeq === 'function') {
        deleteSeq.call(this._keystore, this._aid, this._deviceId, this._slotId, ns);
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

  /** 记录 E2EE 自动编排错误 */
  private _logE2eeError(stage: string, groupId: string, aid: string, exc: Error): void {
    try {
      this._dispatcher.publish('e2ee.orchestration_error', {
        stage, group_id: groupId, aid, error: String(exc),
      }).catch(() => {});
    } catch {
      // 日志本身不应阻断主流程
    }
  }

  // ── URL 辅助 ──────────────────────────────────────────────

  /** 跨域时将 Gateway URL 替换为 peer 所在域的 Gateway URL */
  private static _resolvePeerGatewayUrl(localGatewayUrl: string, peerAid: string): string {
    if (!peerAid.includes('.')) return localGatewayUrl;
    const dotIdx = peerAid.indexOf('.');
    const peerIssuer = peerAid.slice(dotIdx + 1);
    const m = localGatewayUrl.match(/gateway\.([^:/]+)/);
    if (!m) return localGatewayUrl;
    const localIssuer = m[1];
    if (localIssuer === peerIssuer) return localGatewayUrl;
    return localGatewayUrl.replace(`gateway.${localIssuer}`, `gateway.${peerIssuer}`);
  }

  /** 构建证书下载 URL */
  private static _certCacheKey(aid: string, certFingerprint?: string): string {
    const normalized = String(certFingerprint ?? '').trim().toLowerCase();
    return normalized ? `${aid}#${normalized}` : aid;
  }

  private static _buildCertUrl(gatewayUrl: string, aid: string, certFingerprint?: string): string {
    const parsed = new URL(gatewayUrl);
    const scheme = parsed.protocol === 'wss:' ? 'https:' : 'http:';
    const url = new URL(`${scheme}//${parsed.host}/pki/cert/${encodeURIComponent(aid)}`);
    const normalized = String(certFingerprint ?? '').trim().toLowerCase();
    if (normalized) {
      url.searchParams.set('cert_fingerprint', normalized);
    }
    return url.toString();
  }

  // ── 内部：连接 ────────────────────────────────────────────

  /** 执行一次连接流程 */
  private async _connectOnce(params: ConnectParams, allowReauth: boolean): Promise<void> {
    const tStart = Date.now();
    const gatewayUrl = this._resolveGateway(params);
    this._gatewayUrl = gatewayUrl;
    this._slotId = String(params.slot_id ?? '');
    this._captureCapabilitiesFromConnect(params);
    this._connectDeliveryMode = { ...(params.delivery_mode ?? this._connectDeliveryMode) };
    const extraInfo = (params.extra_info && typeof params.extra_info === 'object' && !Array.isArray(params.extra_info))
      ? params.extra_info as Record<string, unknown>
      : undefined;
    const prevState = this._state;
    this._auth.setInstanceContext({ deviceId: this._deviceId, slotId: this._slotId });
    this._state = 'connecting';
    this._clientLog.debug(`_connectOnce enter: gateway=${gatewayUrl}, allowReauth=${allowReauth}`);

    // 前置 restore：在 transport.connect 启动 reader 之前完成，
    // 避免 reader 把积压 push 交给空 tracker 的 handler，触发 S2 历史 gap 误补拉。
    this._refreshSeqTrackerContext();
    this._restoreSeqTrackerState();

    try {
      const challenge = await this._transport.connect(gatewayUrl);
      this._clientLog.debug(`WebSocket connection established: gateway=${gatewayUrl}`);
      this._state = 'authenticating';

      if (allowReauth) {
        const authContext = await this._auth.connectSession(
          this._transport,
          challenge,
          gatewayUrl,
          {
            accessToken: String(params.access_token ?? ''),
            deviceId: this._deviceId,
            slotId: this._slotId,
            deliveryMode: this._connectDeliveryMode,
            connectionKind: String(params.connection_kind ?? 'long'),
            shortTtlMs: Number(params.short_ttl_ms ?? 0),
            extraInfo,
          },
        );
        if (isJsonObject(authContext)) {
          const auth = authContext as AuthContext;
          const identity = auth.identity;
          if (identity && isJsonObject(identity)) {
            this._identity = identity;
            this._aid = String(identity.aid ?? this._aid ?? '');
            if (this._aid) this._logger.bindAid(this._aid);
            if (this._sessionParams !== null) {
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
            extraInfo,
          },
        );
        this._syncIdentityAfterConnect(String(params.access_token));
        if (isJsonObject(hello) && 'heartbeat_interval' in hello) {
          this._applyServerHeartbeatInterval(hello.heartbeat_interval, 'auth');
        }
      }

      this._state = 'ready';
      this._connectedAt = Date.now();
      this._clientLog.debug(`auth complete, connection ready: aid=${this._aid ?? ''}, gateway=${gatewayUrl}`);
      await this._dispatcher.publish('state_change', { state: this._publicState(this._state), gateway: gatewayUrl });

      // auth 阶段 aid 可能被 identity 覆盖（上方 this._aid = identity.aid）；
      // 若 context 发生变化，重新 refresh + restore，保持 tracker 与真实身份一致。
      if (this._seqTrackerContext !== this._currentSeqTrackerContext()) {
        this._refreshSeqTrackerContext();
        this._restoreSeqTrackerState();
      }

      this._startBackgroundTasks();

      // V2 E2EE：初始化 session 并注册本设备 SPK。
      try {
        await this._initV2Session();
      } catch (exc) {
        this._clientLog.warn(`V2 session init failed (non-fatal): ${formatCaughtError(exc)}`);
      }

      // connect/reconnect 成功后自动触发一次 P2P message.v2.pull，补齐离线期间积压
      // 群消息按惰性触发，不在此处主动 pull
      void this._fillP2pGap().catch((exc) => {
        this._clientLog.warn(`schedule post-connect P2P gap fill failed: ${formatCaughtError(exc)}`);
      });
      this._clientLog.debug(`_connectOnce exit: elapsed=${Date.now() - tStart}ms gateway=${gatewayUrl}, aid=${this._aid ?? ''}`);
    } catch (err) {
      this._state = (prevState === 'connected' || prevState === 'ready') ? 'standby' : (this._currentAid ? 'standby' : 'no_identity');
      this._clientLog.debug(`_connectOnce exit (error): elapsed=${Date.now() - tStart}ms gateway=${gatewayUrl} err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 记录当前 connect 声明的 E2EE 能力；缺失时按 SDK 默认能力（V2）处理。 */
  private _captureCapabilitiesFromConnect(params: ConnectParams): void {
    void params;
    this._connectCapabilities = {
      e2ee: true,
      group_e2ee: true,
      supported_p2p_e2ee: ['e2ee_v2'],
      supported_group_e2ee: ['group_e2ee_v2'],
    };
  }

  /** 当前连接是否按 V2 P2P E2EE 处理；未声明 capabilities 时视同支持 V2。 */
  private _clientUsesV2P2P(): boolean {
    return true;
  }

  /** 当前连接是否按 V2 Group E2EE 处理；未声明 capabilities 时视同支持 V2。 */
  private _clientUsesV2Group(): boolean {
    return true;
  }

  /** 后台 Promise 统一兜底，避免事件回调里的异步异常变成未处理拒绝。 */
  private _safeAsync(promise: Promise<unknown>): void {
    promise.catch((exc) => {
      this._clientLog.warn(`background task exception: ${formatCaughtError(exc)}`);
    });
  }

  /** V2-only：所有加密入口都必须有 V2 session。 */
  private async _ensureV2SessionReady(method: string, errorMessage?: string): Promise<void> {
    if (!this._v2Session) {
      throw new StateError(errorMessage ?? `V2 session not initialized; encrypted ${method} requires E2EE V2`);
    }
  }

  private _v2CallFn(): CallFn {
    return async (method, params) =>
      this.call(method, params as RpcParams) as Promise<Record<string, unknown> | unknown>;
  }

  /**
   * 初始化 V2 session：IK 使用 AID 长期私钥，SPK 存储在 per-AID SQLite 的 v2_device_keys 表。
   * connect 成功后会自动调用；重复调用幂等。
   */
  private async _initV2Session(): Promise<void> {
    if (!this._aid) return;
    const existing = this._v2Session;
    if (existing && existing.aid === this._aid && existing.deviceId === this._deviceId) {
      return;
    }
    if (existing) {
      this._v2BootstrapCache.clear();
    }

    let identity = this._identity;
    if (!identity) {
      try {
        identity = this._keystore.loadIdentity(this._aid);
        if (identity) this._identity = identity;
      } catch {
        identity = null;
      }
    }
    if (!identity?.private_key_pem) {
      // fallback：缓存的 identity 可能被 instanceState 污染，重新从 keystore 加载
      try {
        identity = this._keystore.loadIdentity(this._aid);
        if (identity?.private_key_pem) {
          this._identity = identity;
          this._clientLog.warn('V2 session init: identity cache was stale, reloaded from keystore');
          // 重新持久化 instance_state，清理脏数据
          const persistIdentity = (this._auth as any)._persistIdentity as ((value: IdentityRecord) => void) | undefined;
          if (typeof persistIdentity === 'function') {
            try { persistIdentity.call(this._auth, identity); } catch { /* best-effort */ }
          }
        }
      } catch {
        identity = null;
      }
    }
    if (!identity?.private_key_pem) {
      this._clientLog.warn('V2 session init skipped: no AID private key');
      return;
    }

    const privateKey = crypto.createPrivateKey(String(identity.private_key_pem));
    const jwk = privateKey.export({ format: 'jwk' }) as unknown as {
      kty?: string;
      crv?: string;
      d?: string;
    };
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.d) {
      throw new StateError('AID private key must be EC P-256');
    }
    const aidPriv = _v2LeftPad32(_v2B64uToBytes(jwk.d));
    const pubDer = crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' }) as Buffer;
    const aidPubDer = new Uint8Array(pubDer);

    const storeProvider = this._keystore as KeyStore & {
      getV2KeyStore?: (aid: string) => V2KeyStore;
    };
    const v2Store = storeProvider.getV2KeyStore?.call(this._keystore, this._aid);
    if (!v2Store) {
      throw new StateError('V2 key store is unavailable for current keystore');
    }

    this._v2KeyStore = v2Store;
    this._v2Session = new V2Session(v2Store, this._deviceId, this._aid, aidPriv, aidPubDer);
    await this._v2Session.ensureRegistered(this._v2CallFn());
    this._clientLog.debug(`V2 session initialized aid=${this._aid} device=${this._deviceId}`);
    // 群 state proposal 由服务端在 client.online 时定向通知。
  }

  private async _v2TrustedIKPubDer(aid: string): Promise<Uint8Array> {
    const normalizedAid = String(aid ?? '').trim();
    if (!normalizedAid) throw new E2EEError('spk_aid_missing');
    if (this._aid && normalizedAid === this._aid) {
      if (!this._v2Session) throw new E2EEError('V2 session not initialized');
      return this._v2Session.currentIkPubDer;
    }
    const certPem = await this._fetchPeerCert(normalizedAid);
    const cert = new crypto.X509Certificate(certPem);
    const certPubDer = cert.publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
    return new Uint8Array(certPubDer);
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
    const expectedSpkId = `sha256:${crypto.createHash('sha256').update(Buffer.from(args.spkPkDer)).digest('hex').slice(0, 16)}`;
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
    const tsText = this._v2SPKTimestampText(args.dev.spk_timestamp, args.aid, args.deviceId, spkId);
    const signData = Buffer.concat([
      Buffer.from(args.spkPkDer),
      Buffer.from(spkId, 'utf8'),
      Buffer.from(tsText, 'utf8'),
    ]);
    if (!ecdsaVerifyRaw(trustedIK, signature, new Uint8Array(signData))) {
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
    const senderPubDer = session.getPeerIK(fromAid, senderDeviceId);
    if (senderPubDer) return senderPubDer;

    try {
      const certPem = await this._fetchPeerCert(fromAid, undefined, 3000);
      const cert = new crypto.X509Certificate(certPem);
      const certPubDer = cert.publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
      const certPub = new Uint8Array(certPubDer);
      session.cachePeerIK(fromAid, senderDeviceId, certPub);
      this._clientLog.debug(`V2 decrypt: sender IK fallback from PKI cert for ${fromAid}`);
      return certPub;
    } catch (exc) {
      this._clientLog.warn(`V2 decrypt: PKI cert sender IK fallback failed for ${fromAid}: ${formatCaughtError(exc)}`);
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
    if (!session || !isJsonObject(dev as JsonValue | object | null | undefined)) return;
    const device = dev as Record<string, unknown>;
    const devId = getV2DeviceId(device);
    const aid = String(device.aid ?? fallbackAid ?? '').trim();
    const ikPk = String(device.ik_pk ?? '').trim();
    if (!devId.present || !aid || !ikPk) return;
    try {
      session.cachePeerIK(aid, devId.value, _v2B64ToBytes(ikPk));
    } catch (exc) {
      this._clientLog.debug(`V2 sender IK cache from bootstrap skipped aid=${aid} dev=${devId.value}: ${formatCaughtError(exc)}`);
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
          await this._primeBootstrapPeerCerts(bs, fromAid);
          const peers = (Array.isArray(bs?.peer_devices) ? bs.peer_devices : []) as Array<Record<string, unknown>>;
          for (const dev of peers) this._cacheV2PeerIKFromDevice(dev, fromAid);
        } catch (exc) {
          this._clientLog.warn(`V2 sender IK pending bootstrap failed peer=${fromAid}: ${formatCaughtError(exc)}`);
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
            this._clientLog.warn(`V2 sender IK pending group bootstrap failed group=${groupId}: ${formatCaughtError(exc)}`);
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
          this._clientLog.warn(`V2 sender IK pending retry raised: key=${key} err=${formatCaughtError(exc)}`);
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
   * 构造 V2 P2P envelope；message.send 与 message.thought.put 共用。
   */
  private async _buildV2P2PEnvelope(opts: {
    to: string;
    payload: Record<string, unknown>;
    messageId?: string;
    timestamp?: number;
    useCache?: boolean;
    protectedHeaders?: ProtectedHeadersInput;
    context?: Record<string, unknown>;
  }): Promise<Record<string, unknown>> {
    if (!this._v2Session) {
      throw new StateError('V2 session not initialized');
    }
    const session = this._v2Session;
    const to = String(opts.to ?? '').trim();
    if (!to) throw new ValidationError("message.send requires 'to'");
    const useCache = opts.useCache !== false;

    let peerDevices: Array<Record<string, unknown>> = [];
    let auditRaw: Array<Record<string, unknown>> = [];
    let wrapPolicy = normalizeV2WrapPolicy(undefined);
    const cached = useCache ? this._v2BootstrapCache.get(to) : undefined;
    if (cached && Date.now() - cached.cachedAt < AUNClient.V2_BOOTSTRAP_TTL_MS) {
      peerDevices = cached.devices;
      auditRaw = cached.auditRecipients;
      wrapPolicy = cached.wrapPolicy ?? wrapPolicy;
      this._clientLog.debug(`message.v2.bootstrap cache hit: to=${to}, devices=${peerDevices.length}, audit=${auditRaw.length}`);
    } else {
      const bs = await this.call('message.v2.bootstrap', {
        peer_aid: to,
        e2ee_wrap_capabilities: v2WrapCapabilities(),
      }) as Record<string, unknown>;
      await this._primeBootstrapPeerCerts(bs, to);
      wrapPolicy = normalizeV2WrapPolicy(bs.e2ee_wrap_policy);
      peerDevices = (Array.isArray(bs?.peer_devices) ? bs.peer_devices : []) as Array<Record<string, unknown>>;
      auditRaw = (Array.isArray(bs?.audit_recipients) ? bs.audit_recipients : []) as Array<Record<string, unknown>>;
      this._clientLog.debug(`message.v2.bootstrap fetched: to=${to}, devices=${peerDevices.length}, audit=${auditRaw.length}`);
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

    const auditTargets: Target[] = [];
    for (const dev of auditRaw) {
      const target = await this._v2BuildTargetFromDevice({
        dev,
        aid: String(dev.aid ?? ''),
        deviceId: String(dev.device_id ?? ''),
        role: 'audit',
        defaultKeySource: 'peer_device_prekey',
      });
      if (target) auditTargets.push(target);
    }

    // self-sync：给同 AID 其它在线/注册设备也 wrap 一份。
    if (this._aid && this._aid !== to) {
      try {
        const selfCached = this._v2BootstrapCache.get(this._aid);
        let selfDevices: Array<Record<string, unknown>> = [];
        if (selfCached && Date.now() - selfCached.cachedAt < AUNClient.V2_BOOTSTRAP_TTL_MS) {
          selfDevices = selfCached.devices;
        } else {
          const selfBs = await this.call('message.v2.bootstrap', {
            peer_aid: this._aid,
            e2ee_wrap_capabilities: v2WrapCapabilities(),
          }) as Record<string, unknown>;
          await this._primeBootstrapPeerCerts(selfBs, this._aid);
          selfDevices = (Array.isArray(selfBs?.peer_devices) ? selfBs.peer_devices : []) as Array<Record<string, unknown>>;
          const selfWrapPolicy = normalizeV2WrapPolicy(selfBs.e2ee_wrap_policy);
          if (selfDevices.length > 0) {
            this._v2BootstrapCache.set(this._aid, {
              devices: selfDevices,
              auditRecipients: [],
              cachedAt: Date.now(),
              wrapPolicy: selfWrapPolicy,
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
        this._clientLog.debug(`V2 self-sync bootstrap failed (non-fatal): ${formatCaughtError(exc)}`);
      }
    }

    if (targets.length === 0) {
      throw new E2EEError(`V2 bootstrap: no usable devices found for ${to}`);
    }
    const envelope = encryptP2PMessage(
      session.getSenderIdentity(),
      {
        targets: applyV2WrapPolicyToTargets(targets, wrapPolicy),
        auditRecipients: applyV2WrapPolicyToTargets(auditTargets, wrapPolicy),
      },
      opts.payload,
      {
        messageId: opts.messageId,
        timestamp: opts.timestamp,
        protectedHeaders: opts.protectedHeaders,
        context: opts.context,
      },
    );
    this._logMessageDebug('send-envelope', 'message.send.v2', 'message.send', {
      message_id: envelope.message_id,
      to,
      type: envelope.type,
      version: envelope.version,
      protected_headers: envelope.protected_headers,
      context: envelope.context,
    }, {
      payloadOverride: envelope,
      extra: {
        plaintext_payload: opts.payload,
        target_count: targets.length,
        audit_count: auditTargets.length,
        use_cache: useCache,
      },
    });
    return envelope;
  }

  /** V2 P2P 加密发送，推测性缓存失败后刷新 bootstrap 重试一次。 */
  private async _sendV2(
    to: string,
    payload: Record<string, unknown>,
    opts?: { messageId?: string; timestamp?: number; protectedHeaders?: ProtectedHeadersInput; context?: Record<string, unknown> },
  ): Promise<unknown> {
    await this._ensureV2SessionReady(
      'message.send',
      'V2 session not initialized; encrypted message.send requires V2 (V1 E2EE removed)',
    );
    const toAid = String(to ?? '').trim();
    if (!toAid) throw new ValidationError("message.send requires 'to'");
    if (!isJsonObject(payload)) throw new ValidationError('message.send payload must be a dict for V2 encryption');
    this._logMessageDebug('send-plaintext', 'message.send.v2', 'message.send', {
      to: toAid,
      message_id: opts?.messageId ?? '',
      payload,
    }, { payloadOverride: payload });
    const attempt = async (useCache: boolean): Promise<unknown> => {
      this._clientLog.debug(`message.v2.send attempt: to=${toAid}, use_cache=${useCache}`);
      const envelope = await this._buildV2P2PEnvelope({
        to: toAid,
        payload,
        messageId: opts?.messageId,
        timestamp: opts?.timestamp,
        protectedHeaders: opts?.protectedHeaders,
        context: opts?.context,
        useCache,
      });
      const result = await this.call('message.send', {
        to: toAid,
        payload: envelope as JsonObject,
        encrypt: false,
      });
      this._clientLog.debug(`message.v2.send ok: to=${toAid}, use_cache=${useCache}, seq=${String((isJsonObject(result as JsonValue | object | null | undefined) ? (result as JsonObject).seq : '') ?? '')}`);
      return result;
    };
    try {
      return await attempt(true);
    } catch (exc) {
      const excCode = (exc as { code?: unknown })?.code;
      if (AUNClient.V2_RETRYABLE_CODES.has(Number(excCode))) {
        this._clientLog.debug(`V2 P2P speculative send rejected (code=${String(excCode)}), refreshing bootstrap`);
        this._v2BootstrapCache.delete(toAid);
        return await attempt(false);
      }
      throw exc;
    }
  }

  /** V2 P2P 拉取并解密；直接方法返回消息数组，call("message.pull") 会包装为 {messages}. */
  private async _pullV2(
    afterSeq: number = 0,
    limit: number = 50,
    opts?: { skipAutoAck?: boolean; gateLocked?: boolean; scheduleFollowup?: boolean; force?: boolean },
  ): Promise<Array<Record<string, unknown>>> {
    await this._ensureV2SessionReady('message.pull');
    const ns = this._aid ? `p2p:${this._aid}` : '';
    if (ns && !opts?.gateLocked) {
      return await this._runPullSerialized(ns, async () => this._pullV2(afterSeq, limit, {
        ...(opts ?? {}),
        gateLocked: true,
        scheduleFollowup: true,
      }));
    }
    const decrypted: Array<Record<string, unknown>> = [];
    let totalRawCount = 0;
    let nextAfterSeq = opts?.force ? afterSeq : (afterSeq || (ns ? this._seqTracker.getContiguousSeq(ns) : 0));
    let pageCount = 0;
    const maxPages = 100;

    while (pageCount < maxPages) {
      pageCount += 1;
      this._clientLog.debug(`message.v2.pull page request: page=${pageCount}, after_seq=${nextAfterSeq}, limit=${limit}, ns=${ns || '<none>'}`);
      const result = await this._callRawV2Rpc('message.v2.pull', {
        after_seq: nextAfterSeq,
        limit,
        ...(opts?.force ? { force: true } : {}),
      }) as Record<string, unknown>;
      const messages = (Array.isArray(result?.messages) ? result.messages : []) as Array<Record<string, unknown>>;
      totalRawCount += messages.length;
      this._clientLog.debug(`message.v2.pull page response: page=${pageCount}, raw_count=${messages.length}, has_more=${String(result.has_more ?? '')}, server_ack_seq=${String(result.server_ack_seq ?? '')}`);
      for (const msg of messages) {
        this._logMessageDebug('pull-raw', 'message.v2.pull', 'message.received', msg);
      }
      const seqs = messages
        .map((msg) => Number(msg.seq ?? 0))
        .filter((seq) => Number.isFinite(seq) && seq > 0);
      const pageContigBefore = ns ? this._seqTracker.getContiguousSeq(ns) : 0;
      let pageMaxSeq = nextAfterSeq;
      if (seqs.length > 0) {
        pageMaxSeq = Math.max(...seqs);
        if (ns) {
          this._seqTracker.forceContiguousSeq(ns, pageMaxSeq);
          this._clientLog.debug(`message.v2.pull force contiguous: ns=${ns}, page_max_seq=${pageMaxSeq}, previous=${pageContigBefore}`);
        }
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
          if (legacyPayload !== undefined && legacyPayload !== null && payloadType !== 'e2ee.encrypted' && payloadType !== 'e2ee.group_encrypted') {
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
          if (ns) {
            await this._publishPulledMessage('message.received', ns, seq, v1Msg as EventPayload);
          } else {
            await this._publishAppEvent('message.received', v1Msg as EventPayload, 'pull');
          }
          decrypted.push(v1Msg);
          this._clientLog.debug(`message.v2.pull plaintext V1 delivered: seq=${seq}, ns=${ns || '<none>'}`);
        } else {
            this._clientLog.debug(`message.v2.pull skipping V1 envelope seq=${seq} payload_type=${payloadType || '<none>'} (V1 E2EE removed)`);
          }
          continue;
        }

        if (version !== 'v2') {
          this._clientLog.debug(`message.v2.pull skipping non-V2 row seq=${seq} version=${String(msg.version ?? '')}`);
          continue;
        }

        const spkId = String(msg.spk_id ?? '');
        if (spkId && this._v2Session && !this._v2Session.isCurrentSPK(spkId)) {
          this._v2Session.trackOldSPKMaxSeq(spkId, seq);
        }
        const plaintext = await this._decryptV2Message(msg);
        if (plaintext === null) {
          this._clientLog.debug(`message.v2.pull decrypt returned null: seq=${seq}, ns=${ns || '<none>'}`);
          continue;
        }
        if (ns) {
          await this._publishPulledMessage('message.received', ns, seq, plaintext as EventPayload);
        } else {
          await this._publishAppEvent('message.received', plaintext as EventPayload, 'pull');
        }
        decrypted.push(plaintext);
        this._logMessageDebug('decrypt-ok', 'message.v2.pull', 'message.received', plaintext);
      }

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
          await this._drainOrderedMessages(ns, undefined, true);
          this._saveSeqTrackerState();
        }
        if (messages.length > 0 && contigAdvanced && ackSeq > 0 && !opts?.skipAutoAck) {
          this._clientLog.debug(`message.v2.pull scheduling auto-ack: ns=${ns}, ack_seq=${ackSeq}, raw_count=${messages.length}`);
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
    this._clientLog.debug(`message.v2.pull done: requested_after_seq=${afterSeq}, pages=${pageCount}, decrypted=${decrypted.length}, ns=${ns || '<none>'}`);
    return decrypted;
  }

  /** V2 P2P ack，并触发旧 SPK 销毁自检。 */
  private async _ackV2(upToSeq?: number): Promise<unknown> {
    const ns = this._aid ? `p2p:${this._aid}` : '';
    let seq = Number(upToSeq ?? (ns ? this._seqTracker.getContiguousSeq(ns) : 0));
    if (!Number.isFinite(seq) || seq <= 0) {
      this._clientLog.debug(`message.v2.ack skipped: ns=${ns || '<none>'}, up_to_seq=${String(upToSeq ?? '')}`);
      return { acked: 0 };
    }
    // ack clamp：永远不发送超过 maxSeenSeq 的 up_to_seq
    if (ns) {
      const maxSeen = this._seqTracker.getMaxSeenSeq(ns);
      if (maxSeen > 0 && seq > maxSeen) {
        this._clientLog.warn(`ackV2 clamp: up_to_seq=${seq} > max_seen=${maxSeen}, clamp`);
        seq = maxSeen;
      }
    }
    this._clientLog.debug(`message.v2.ack send: ns=${ns || '<none>'}, up_to_seq=${seq}`);
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
        const destroyed = this._v2Session.maybeDestroyOldSPKs(actualAckSeq);
        if (destroyed.length > 0) {
          this._clientLog.info(`V2 destroyed old SPKs after ack: ${destroyed.slice(0, 3).join(',')} (PFS)`);
        }
      } catch (exc) {
        this._clientLog.debug(`V2 SPK destroy failed (non-fatal): ${formatCaughtError(exc)}`);
      }
    }
    this._clientLog.debug(`message.v2.ack ok: ns=${ns || '<none>'}, requested=${seq}, effective=${actualAckSeq}, acked=${String(result.acked ?? '')}`);
    return result;
  }

  /** V2 Group 加密发送，推测性缓存失败后刷新 bootstrap 重试一次。 */
  private async _sendGroupV2(
    groupId: string,
    payload: Record<string, unknown>,
    opts?: { messageId?: string; timestamp?: number; protectedHeaders?: ProtectedHeadersInput; context?: Record<string, unknown> },
  ): Promise<unknown> {
    await this._ensureV2SessionReady(
      'group.send',
      'V2 session not initialized; encrypted group.send requires V2 (V1 E2EE removed)',
    );
    const gid = normalizeGroupId(groupId) || String(groupId ?? '').trim();
    if (!gid) throw new ValidationError("group.send requires 'group_id'");
    if (!isJsonObject(payload)) throw new ValidationError('group.send payload must be a dict for V2 encryption');
    this._logMessageDebug('send-plaintext', 'group.send.v2', 'group.send', {
      group_id: gid,
      message_id: opts?.messageId ?? '',
      payload,
    }, { payloadOverride: payload });

    const attempt = async (useCache: boolean): Promise<unknown> => {
      this._clientLog.debug(`group.v2.send attempt: group=${gid}, use_cache=${useCache}`);
      const envelope = await this._buildV2GroupEnvelope({
        groupId: gid,
        payload,
        messageId: opts?.messageId,
        timestamp: opts?.timestamp,
        protectedHeaders: opts?.protectedHeaders,
        context: opts?.context,
        useCache,
      });
      const result = await this.call('group.v2.send', {
        group_id: gid,
        envelope: envelope as JsonObject,
      });
      this._clientLog.debug(`group.v2.send ok: group=${gid}, use_cache=${useCache}, seq=${String((isJsonObject(result as JsonValue | object | null | undefined) ? (result as JsonObject).seq : '') ?? '')}`);
      return result;
    };

    const markSentSeq = (result: unknown): void => {
      if (!isJsonObject(result as JsonValue | object | null | undefined)) return;
      const obj = result as JsonObject;
      const seq = Number(obj.seq ?? 0);
      if (!Number.isFinite(seq) || seq <= 0) return;
      const ns = `group:${gid}`;
      this._seqTracker.onMessageSeq(ns, seq);
      this._markPublishedSeq(ns, seq);
      this._saveSeqTrackerState();
      this._clientLog.debug(`group.v2.send marked own seq: group=${gid}, ns=${ns}, seq=${seq}`);
    };

    try {
      const result = await attempt(true);
      markSentSeq(result);
      return result;
    } catch (exc) {
      const excCode = Number((exc as { code?: unknown })?.code);
      if (AUNClient.V2_RETRYABLE_CODES.has(excCode)) {
        this._clientLog.debug(`V2 group speculative send rejected (code=${String(excCode)}), refreshing bootstrap`);
        this._v2BootstrapCache.delete(`group:${gid}`);
        const result = await attempt(false);
        markSentSeq(result);
        return result;
      }
      throw exc;
    }
  }

  /** 构造 V2 Group envelope；group.send 与 group.thought.put 共用。 */
  private async _buildV2GroupEnvelope(opts: {
    groupId: string;
    payload: Record<string, unknown>;
    messageId?: string;
    timestamp?: number;
    useCache?: boolean;
    protectedHeaders?: ProtectedHeadersInput;
    context?: Record<string, unknown>;
  }): Promise<Record<string, unknown>> {
    if (!this._v2Session) throw new StateError('V2 session not initialized');
    const session = this._v2Session;
    const groupId = normalizeGroupId(opts.groupId) || String(opts.groupId ?? '').trim();
    if (!groupId) throw new ValidationError("group.send requires 'group_id'");
    const cacheKey = `group:${groupId}`;
    const useCache = opts.useCache !== false;

    let allDevices: Array<Record<string, unknown>> = [];
    let auditRecipientsRaw: Array<Record<string, unknown>> = [];
    let epoch = 0;
    let stateCommitment: StateCommitmentAAD = { state_version: 0, state_hash: '', state_chain: '' };
    let wrapPolicy = normalizeV2WrapPolicy(undefined);

    const cached = useCache ? this._v2BootstrapCache.get(cacheKey) : undefined;
    if (cached && Date.now() - cached.cachedAt < AUNClient.V2_BOOTSTRAP_TTL_MS) {
      allDevices = cached.devices;
      auditRecipientsRaw = cached.auditRecipients;
      epoch = cached.epoch ?? 0;
      stateCommitment = cached.stateCommitment ?? stateCommitment;
      wrapPolicy = cached.wrapPolicy ?? wrapPolicy;
      this._clientLog.debug(`group.v2.bootstrap cache hit: group=${groupId}, devices=${allDevices.length}, audit=${auditRecipientsRaw.length}, epoch=${epoch}, state_version=${stateCommitment.state_version}`);
    } else {
      const bs = await this.call('group.v2.bootstrap', {
        group_id: groupId,
        e2ee_wrap_capabilities: v2WrapCapabilities(),
      }) as Record<string, unknown>;
      allDevices = (Array.isArray(bs.devices) ? bs.devices : []) as Array<Record<string, unknown>>;
      auditRecipientsRaw = (Array.isArray(bs.audit_recipients) ? bs.audit_recipients : []) as Array<Record<string, unknown>>;
      epoch = Number(bs.epoch ?? 0) || 0;
      wrapPolicy = normalizeV2WrapPolicy(bs.e2ee_wrap_policy);
      this._clientLog.debug(`group.v2.bootstrap fetched: group=${groupId}, devices=${allDevices.length}, audit=${auditRecipientsRaw.length}, epoch=${epoch}, members=${Array.isArray(bs.member_aids) ? bs.member_aids.length : 0}`);
      const stateChain = String(bs.state_chain ?? '');
      await this._v2CheckFork(groupId, stateChain);
      await this._v2VerifyStateSignature(groupId, bs);
      await this._publishV2GroupSecurityLevel(groupId, bs);
      stateCommitment = {
        state_version: Number(bs.state_version ?? 0) || 0,
        state_hash: String(bs.state_hash_signed ?? bs.state_hash ?? ''),
        state_chain: stateChain,
      };
      if (allDevices.length > 0) {
        this._v2BootstrapCache.set(cacheKey, {
          devices: allDevices,
          auditRecipients: auditRecipientsRaw,
          cachedAt: Date.now(),
          epoch,
          stateCommitment,
          wrapPolicy,
        });
      }
      // lazy sync 触发：发现 pending members 时异步发起提案
      const pendingAdds = Array.isArray(bs.pending_adds) ? bs.pending_adds : [];
      if (pendingAdds.length > 0 && this._v2Session) {
        this._v2MaybeTriggerAutoPropose(groupId);
      }
    }

    if (allDevices.length === 0) {
      throw new E2EEError(`V2 group bootstrap: no devices found for group ${groupId}`);
    }

    const targets: Target[] = [];
    for (const dev of allDevices) {
      const devAid = String(dev.aid ?? '').trim();
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
    if (targets.length === 0) {
      throw new E2EEError(`V2 group: no target devices for group ${groupId}`);
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

    const envelope = encryptGroupMessage(
      session.getSenderIdentity(),
      groupId,
      epoch,
      applyV2WrapPolicyToTargets(targets, wrapPolicy),
      opts.payload,
      {
        messageId: opts.messageId,
        timestamp: opts.timestamp,
        protectedHeaders: opts.protectedHeaders,
        context: opts.context,
      },
      stateCommitment,
    );
    this._logMessageDebug('send-envelope', 'group.send.v2', 'group.send', {
      group_id: groupId,
      message_id: envelope.message_id,
      type: envelope.type,
      version: envelope.version,
      protected_headers: envelope.protected_headers,
      context: envelope.context,
    }, {
      payloadOverride: envelope,
      extra: {
        plaintext_payload: opts.payload,
        epoch,
        target_count: targets.length,
        audit_count: auditRecipientsRaw.length,
        state_version: stateCommitment.state_version,
        use_cache: useCache,
      },
    });
    return envelope;
  }

  private async _pullGroupV2Internal(params: { group_id: string; after_seq: number; limit: number }): Promise<void> {
    await this._pullGroupV2(params.group_id, params.after_seq, params.limit, { gateLocked: true });
  }

  /** V2 Group 拉取并解密；直接方法返回消息数组，call("group.pull") 会包装为 {messages}. */
  private async _pullGroupV2(
    groupId: string,
    afterSeq: number = 0,
    limit: number = 50,
    opts?: { gateLocked?: boolean; scheduleFollowup?: boolean },
  ): Promise<Array<Record<string, unknown>>> {
    await this._ensureV2SessionReady('group.pull');
    const gid = normalizeGroupId(groupId) || String(groupId ?? '').trim();
    if (!gid) throw new ValidationError('group.pull requires group_id');
    const ns = `group:${gid}`;
    if (!opts?.gateLocked) {
      return await this._runPullSerialized(ns, async () => this._pullGroupV2(gid, afterSeq, limit, {
        ...(opts ?? {}),
        gateLocked: true,
        scheduleFollowup: true,
      }));
    }
    const decrypted: Array<Record<string, unknown>> = [];
    let totalRawCount = 0;
    let nextAfterSeq = afterSeq || this._seqTracker.getContiguousSeq(ns);
    let pageCount = 0;
    const maxPages = 100;

    while (pageCount < maxPages) {
      pageCount += 1;
      this._clientLog.debug(`group.v2.pull page request: group=${gid}, page=${pageCount}, after_seq=${nextAfterSeq}, limit=${limit}, ns=${ns}`);
      const result = await this._callRawV2Rpc('group.v2.pull', {
        group_id: gid,
        after_seq: nextAfterSeq,
        limit,
      }) as Record<string, unknown>;
      const messages = (Array.isArray(result.messages) ? result.messages : []) as Array<Record<string, unknown>>;
      totalRawCount += messages.length;
      const cursor = isJsonObject(result.cursor as JsonValue | object | null | undefined) ? result.cursor as JsonObject : null;
      this._clientLog.debug(`group.v2.pull page response: group=${gid}, page=${pageCount}, raw_count=${messages.length}, has_more=${String(result.has_more ?? '')}, cursor_current=${String(cursor?.current_seq ?? '')}`);
      for (const msg of messages) {
        this._logMessageDebug('pull-raw', 'group.v2.pull', 'group.message_created', msg);
      }
      const seqs = messages
        .map((msg) => Number(msg.seq ?? 0))
        .filter((seq) => Number.isFinite(seq) && seq > 0);
      const pageContigBefore = this._seqTracker.getContiguousSeq(ns);
      let pageMaxSeq = nextAfterSeq;
      if (seqs.length > 0) {
        pageMaxSeq = Math.max(...seqs);
        this._seqTracker.forceContiguousSeq(ns, pageMaxSeq);
        this._clientLog.debug(`group.v2.pull force contiguous: group=${gid}, ns=${ns}, page_max_seq=${pageMaxSeq}, previous=${pageContigBefore}`);
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
              this._clientLog.debug(`group.v2.pull plaintext V1 delivered: group=${gid}, seq=${seq}`);
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
            this._clientLog.debug(`group.v2.pull plaintext V1 delivered: group=${gid}, seq=${seq}`);
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
        if (plaintext === null) {
          this._clientLog.debug(`group.v2.pull decrypt returned null: group=${gid}, seq=${seq}`);
          continue;
        }
        plaintext.group_id = gid;
        await this._publishPulledMessage('group.message_created', ns, seq, plaintext as EventPayload);
        decrypted.push(plaintext);
        this._logMessageDebug('decrypt-ok', 'group.v2.pull', 'group.message_created', plaintext);
      }

      const retentionFloor = this._pullRetentionFloor(result as JsonObject, 'retention_floor_message_seq', 'retention_floor_message_seq');
      if (retentionFloor > 0) {
        const contig = this._seqTracker.getContiguousSeq(ns);
        if (contig < retentionFloor) {
          this._clientLog.info(`group.v2.pull retention-floor advance: ns=${ns} contiguous=${contig} -> retention_floor=${retentionFloor}`);
          this._seqTracker.forceContiguousSeq(ns, retentionFloor);
        }
      }

      const ackSeq = this._seqTracker.getContiguousSeq(ns);
      const contigAdvanced = ackSeq !== pageContigBefore;
      if (contigAdvanced) {
        await this._drainOrderedMessages(ns, undefined, true);
        this._saveSeqTrackerState();
      }
      if (messages.length > 0 && contigAdvanced && ackSeq > 0) {
        this._clientLog.debug(`group.v2.pull scheduling auto-ack: group=${gid}, ns=${ns}, ack_seq=${ackSeq}, raw_count=${messages.length}`);
        this._safeAsync(this._ackGroupV2(gid, ackSeq).then(() => undefined));
      }

      const nextAfter = Math.max(pageMaxSeq, nextAfterSeq);
      if (messages.length === 0 || nextAfter <= nextAfterSeq || result.has_more === false) break;
      nextAfterSeq = nextAfter;
    }

    if (pageCount >= maxPages) {
      this._clientLog.warn(`group.v2.pull reached max_pages=${maxPages} group=${gid} after_seq=${nextAfterSeq}`);
    }
    this._clientLog.debug(`group.v2.pull done: group=${gid}, requested_after_seq=${afterSeq}, pages=${pageCount}, decrypted=${decrypted.length}, ns=${ns}`);
    return decrypted;
  }

  /** V2 Group ack。 */
  private async _ackGroupV2(groupId: string, upToSeq?: number): Promise<unknown> {
    const gid = normalizeGroupId(groupId) || String(groupId ?? '').trim();
    if (!gid) throw new ValidationError('group.ack_messages requires group_id');
    const ns = `group:${gid}`;
    let seq = Number(upToSeq ?? this._seqTracker.getContiguousSeq(ns));
    if (!Number.isFinite(seq) || seq <= 0) {
      this._clientLog.debug(`group.v2.ack skipped: group=${gid}, ns=${ns}, up_to_seq=${String(upToSeq ?? '')}`);
      return { acked: 0 };
    }
    // ack clamp：永远不发送超过 maxSeenSeq 的 up_to_seq
    const maxSeen = this._seqTracker.getMaxSeenSeq(ns);
    if (maxSeen > 0 && seq > maxSeen) {
      this._clientLog.warn(`ackGroupV2 clamp: group=${gid} up_to_seq=${seq} > max_seen=${maxSeen}, clamp`);
      seq = maxSeen;
    }
    this._clientLog.debug(`group.v2.ack send: group=${gid}, ns=${ns}, up_to_seq=${seq}`);
    const result = await this._callRawV2Rpc('group.v2.ack', { group_id: gid, up_to_seq: seq });
    this._clientLog.debug(`group.v2.ack ok: group=${gid}, ns=${ns}, requested=${seq}, result=${this._debugJson(result)}`);
    return result;
  }

  /** 解密单条 V2 pull 消息。缺 sender IK 时先入 pending，后台补齐后重试。 */
  private async _decryptV2Message(msg: Record<string, unknown>, allowPending = true): Promise<Record<string, unknown> | null> {
    const session = this._v2Session;
    if (!session) return null;
    const envelopeJson = msg.envelope_json;
    if (typeof envelopeJson !== 'string' || !envelopeJson) return null;
    let envelope: Record<string, unknown>;
    try {
      envelope = JSON.parse(envelopeJson) as Record<string, unknown>;
    } catch {
      this._clientLog.warn(`V2 decrypt: invalid envelope_json for msg seq=${String(msg.seq)}`);
      return null;
    }
    const e2eeMeta = this._v2E2eeMeta(envelope);
    this._observeAgentMdFromEnvelope(envelope);

    let spkId = '';
    let recipientKeySource = '';
    if (isJsonObject(envelope.recipient as JsonValue | object | null | undefined)) {
      const recipient = envelope.recipient as JsonObject;
      spkId = String(recipient.spk_id ?? '');
      recipientKeySource = String(recipient.key_source ?? '');
    } else if (Array.isArray(envelope.recipients)) {
      spkId = String(msg.spk_id ?? '');
      // 从 recipients 数组中查找本设备对应行，提取 key_source（index 3）
      const recipients = envelope.recipients as unknown[][];
      for (const row of recipients) {
        if (Array.isArray(row) && row.length >= 6
          && String(row[0] ?? '') === this._aid
          && (String(row[1] ?? '') === this._deviceId || String(row[1] ?? '') === '')) {
          if (!spkId) spkId = String(row[5] ?? '');
          if (row.length > 3) recipientKeySource = String(row[3] ?? '');
          break;
        }
      }
    }

    // group_id 只表示群上下文；getGroupDecryptKeys 内部必须按 group SPK -> P2P device SPK -> IK fallback 查找。
    const aad = isJsonObject(envelope.aad as JsonValue | object | null | undefined) ? envelope.aad as JsonObject : {};
    const groupIdForKeys = String(aad.group_id ?? msg.group_id ?? '').trim();
    const undecryptableEvent = groupIdForKeys ? 'group.message_undecryptable' : 'message.undecryptable';
    this._clientLog.debug(`V2 decrypt start: seq=${String(msg.seq ?? '')}, message_id=${String(msg.message_id ?? '')}, group=${groupIdForKeys || '<p2p>'}, from=${String(msg.from_aid ?? '')}, spk_id=${spkId || '<empty>'}, key_source=${recipientKeySource || '<empty>'}, has_recipient=${String(isJsonObject(envelope.recipient as JsonValue | object | null | undefined))}, has_recipients=${String(Array.isArray(envelope.recipients))}`);
    let ikPriv: Uint8Array;
    let spkPriv: Uint8Array | undefined;
    try {
      if (groupIdForKeys) {
        const keys = session.getGroupDecryptKeys(groupIdForKeys, spkId);
        ikPriv = keys.ikPriv;
        spkPriv = keys.spkPriv ?? undefined;
      } else {
        const keys = session.getDecryptKeys(spkId);
        ikPriv = keys.ikPriv;
        spkPriv = keys.spkPriv;
      }
    } catch (exc) {
      this._clientLog.warn(`V2 decrypt: SPK lookup failed seq=${String(msg.seq)} spk_id=${spkId}: ${formatCaughtError(exc)}`);
      const event: JsonObject = {
        message_id:     String(msg.message_id ?? ''),
        from:           String(msg.from_aid ?? ''),
        to:             String(msg.to ?? ''),
        seq:            msg.seq as JsonValue,
        timestamp:      (msg.t_server ?? msg.timestamp) as JsonValue,
        device_id:      String(msg.device_id ?? ''),
        slot_id:        String(msg.slot_id ?? ''),
        _decrypt_error: String(formatCaughtError(exc)),
        _decrypt_stage: 'spk_lookup',
        _envelope_type: String(envelope.type ?? ''),
        _suite:         String(envelope.suite ?? ''),
        _spk_id:        spkId,
      };
      this._attachV2EnvelopeMetadata(event, e2eeMeta);
      this._logMessageDebug('decrypt-fail', 'v2.decrypt', undecryptableEvent, event);
      await this._dispatcher.publish(undecryptableEvent, event);
      return null;
    }
    this._clientLog.debug(`V2 decrypt key lookup ok: seq=${String(msg.seq ?? '')}, group=${groupIdForKeys || '<p2p>'}, ik_len=${ikPriv.byteLength}, spk_len=${spkPriv?.byteLength ?? 0}`);
    const fromAid = String(msg.from_aid ?? '');
    const senderDeviceId = String(aad.from_device ?? '');
    const senderPubDer = await this._getV2SenderPubDer(fromAid, senderDeviceId);
    if (!senderPubDer) {
      this._clientLog.warn(`V2 decrypt: no sender IK for ${fromAid} device=${senderDeviceId}`);
      if (allowPending) {
        this._scheduleV2SenderIKPending({ msg, fromAid, senderDeviceId, groupId: groupIdForKeys });
        return null;
      }
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
      this._attachV2EnvelopeMetadata(event, e2eeMeta);
      this._logMessageDebug('decrypt-fail', 'v2.decrypt', undecryptableEvent, event);
      await this._dispatcher.publish(undecryptableEvent, event);
      return null;
    }

    let plaintext: Record<string, unknown> | null;
    try {
      plaintext = decryptMessage(
        envelope,
        this._aid ?? '',
        this._deviceId,
        ikPriv,
        spkPriv,
        senderPubDer,
      );
    } catch (exc) {
      this._clientLog.warn(`V2 decrypt failed for msg seq=${String(msg.seq)}: ${formatCaughtError(exc)}`);
      const event: JsonObject = {
        message_id:        String(msg.message_id ?? ''),
        from:              fromAid,
        to:                String(msg.to ?? ''),
        seq:               msg.seq as JsonValue,
        timestamp:         (msg.t_server ?? msg.timestamp) as JsonValue,
        device_id:         String(msg.device_id ?? ''),
        slot_id:           String(msg.slot_id ?? ''),
        _decrypt_error:    String(formatCaughtError(exc)),
        _decrypt_stage:    'decrypt',
        _envelope_type:    String(envelope.type ?? ''),
        _suite:            String(envelope.suite ?? ''),
        _sender_device_id: String(aad.from_device ?? ''),
      };
      this._attachV2EnvelopeMetadata(event, e2eeMeta);
      this._logMessageDebug('decrypt-fail', 'v2.decrypt', undecryptableEvent, event);
      await this._dispatcher.publish(undecryptableEvent, event);
      return null;
    }
    if (plaintext === null) {
      this._clientLog.debug(`V2 decrypt returned null plaintext: seq=${String(msg.seq ?? '')}, group=${groupIdForKeys || '<p2p>'}`);
      return null;
    }

    // 消费触发 SPK 轮换
    if (groupIdForKeys && recipientKeySource === 'group_device_prekey' && session.isLastUploadedGroupSPK(groupIdForKeys, spkId)) {
      // Group SPK 消费触发轮换
      const callFn: CallFn = async (method, params) => this.call(method, params as RpcParams) as unknown as Record<string, unknown>;
      session.rotateGroupSPK(groupIdForKeys, callFn).catch(exc => {
        this._clientLog.debug(`V2 group SPK rotation failed (non-fatal): group=${groupIdForKeys} err=${formatCaughtError(exc)}`);
      });
    } else if (groupIdForKeys && recipientKeySource === 'peer_device_prekey') {
      // peer_device_prekey fallback：补注册 group SPK
      const callFn: CallFn = async (method, params) => this.call(method, params as RpcParams) as unknown as Record<string, unknown>;
      session.ensureGroupRegistered(groupIdForKeys, callFn).catch(exc => {
        this._clientLog.debug(`V2 group SPK registration after peer fallback failed (non-fatal): group=${groupIdForKeys} err=${formatCaughtError(exc)}`);
      });
    } else if (!groupIdForKeys && session.isLastUploadedSPK(spkId)) {
      // P2P SPK 消费触发轮换
      const callFn: CallFn = async (method, params) => this.call(method, params as RpcParams) as unknown as Record<string, unknown>;
      session.rotateSPK(callFn).catch(exc => {
        this._clientLog.debug(`V2 SPK rotation failed (non-fatal): ${formatCaughtError(exc)}`);
      });
    }

    const e2ee = this._v2E2eeMeta(envelope);
    const result: JsonObject = {
      message_id: String(msg.message_id ?? ''),
      from: fromAid,
      to: this._aid ?? '',
      seq: msg.seq as JsonValue,
      t_server: msg.t_server as JsonValue,
      payload: plaintext as JsonValue,
      encrypted: true,
      e2ee,
    };
    const explicitDirection = String(msg.direction ?? '').trim();
    result.direction = explicitDirection || (fromAid && fromAid === this._aid ? 'outbound_sync' : 'inbound');
    if (msg.device_id !== undefined) result.device_id = msg.device_id as JsonValue;
    if (msg.slot_id !== undefined) result.slot_id = msg.slot_id as JsonValue;
    this._attachV2EnvelopeMetadata(result, e2ee);
    this._logMessageDebug('decrypt-ok', 'v2.decrypt', groupIdForKeys ? 'group.message_created' : 'message.received', result);
    return result;
  }

  private _v2E2eeMeta(envelope: Record<string, unknown>): JsonObject {
    const suite = String(envelope.suite ?? '');
    const meta: JsonObject = {
      version: 'v2',
      suite,
      encryption_mode: `v2_${suite || 'unknown'}`,
      forward_secrecy: true,
    };
    const protectedHeaders = this._metadataWithoutAuth(envelope.protected_headers);
    if (protectedHeaders && Object.keys(protectedHeaders).length > 0) {
      meta.protected_headers = protectedHeaders;
    }
    const payloadType = String(envelope.payload_type ?? protectedHeaders?.payload_type ?? '').trim();
    if (payloadType) {
      meta.payload_type = payloadType;
    }
    const context = this._metadataWithoutAuth(envelope.context);
    if (context && Object.keys(context).length > 0) {
      meta.context = context;
    }
    const agentMd = this._metadataWithoutAuth(envelope.agent_md);
    if (agentMd && Object.keys(agentMd).length > 0) {
      meta.agent_md = agentMd;
    }
    return meta;
  }

  private _attachV2EnvelopeMetadata(message: JsonObject, meta: JsonObject): void {
    const payloadType = typeof meta.payload_type === 'string' ? meta.payload_type.trim() : '';
    if (payloadType) message.payload_type = payloadType;
    if (isJsonObject(meta.protected_headers)) {
      message.protected_headers = { ...meta.protected_headers } as JsonObject;
    }
    if (isJsonObject(meta.agent_md)) {
      message.agent_md = { ...meta.agent_md } as JsonObject;
    }
  }

  private _attachV2EnvelopeMetadataFromSource(message: JsonObject, source: unknown): void {
    const envelope = this._extractV2EnvelopeFromSource(source);
    if (envelope) {
      this._observeAgentMdFromEnvelope(envelope);
      this._attachV2EnvelopeMetadata(message, this._v2E2eeMeta(envelope));
    }
  }

  private _extractV2EnvelopeFromSource(source: unknown): JsonObject | null {
    const candidate = source as JsonValue | object | null | undefined;
    if (!isJsonObject(candidate)) return null;
    if (isJsonObject(candidate.payload as JsonValue | object | null | undefined)) return candidate.payload as JsonObject;
    if (typeof candidate.envelope_json === 'string' && candidate.envelope_json) {
      try {
        const parsed = JSON.parse(candidate.envelope_json) as unknown;
        if (isJsonObject(parsed as JsonValue | object | null | undefined)) return parsed as JsonObject;
      } catch {
        return null;
      }
    }
    return null;
  }

  private _truthyBool(value: unknown): boolean {
    if (value === true || value === 1) return true;
    if (typeof value === 'string') {
      const normalized = value.trim().toLowerCase();
      return normalized === 'true' || normalized === '1' || normalized === 'yes' || normalized === 'on';
    }
    return false;
  }

  private _encryptedPushEnvelope(msg: JsonObject): JsonObject | null {
    const payload = msg.payload;
    if (this._isEncryptedEnvelopePayload(payload)) return payload as JsonObject;
    if (typeof msg.envelope_json === 'string' && msg.envelope_json.trim()) {
      try {
        const parsed = JSON.parse(msg.envelope_json) as unknown;
        if (this._isEncryptedEnvelopePayload(parsed)) return parsed as JsonObject;
      } catch {
        return null;
      }
    }
    return null;
  }

  private _isEncryptedPushMessage(msg: JsonObject): boolean {
    if (this._truthyBool(msg.encrypted)) return true;
    return this._encryptedPushEnvelope(msg) !== null;
  }

  private _isEncryptedEnvelopePayload(payload: unknown): boolean {
    if (!isJsonObject(payload as JsonValue | object | null | undefined)) return false;
    const envelope = payload as JsonObject;
    const payloadType = String(envelope.type ?? '').trim();
    if (payloadType.startsWith('e2ee.')) return true;
    if (!String(envelope.ciphertext ?? '').trim()) return false;
    return envelope.nonce !== undefined
      || envelope.tag !== undefined
      || envelope.recipient !== undefined
      || envelope.recipients !== undefined
      || envelope.wrapped_key !== undefined
      || envelope.recipients_digest !== undefined;
  }

  private _isV2EncryptedEnvelopePayload(envelope: JsonObject | null): envelope is JsonObject {
    if (!envelope) return false;
    const payloadType = String(envelope.type ?? '').trim();
    if (payloadType === 'e2ee.p2p_encrypted' || payloadType === 'e2ee.group_encrypted') return true;
    return String(envelope.version ?? '').trim().toLowerCase() === 'v2' && payloadType.startsWith('e2ee.');
  }

  private _safeUndecryptablePushEvent(msg: JsonObject, group: boolean): JsonObject {
    const event: JsonObject = {
      message_id: msg.message_id as JsonValue,
      from: msg.from as JsonValue,
      seq: msg.seq as JsonValue,
      timestamp: (msg.timestamp ?? msg.t_server) as JsonValue,
      device_id: msg.device_id as JsonValue,
      slot_id: msg.slot_id as JsonValue,
      _decrypt_error: 'encrypted push payload is not decryptable on raw push path',
      _decrypt_stage: 'push_envelope',
    };
    if (group) {
      event.group_id = msg.group_id as JsonValue;
    } else {
      event.to = msg.to as JsonValue;
    }
    const envelope = this._encryptedPushEnvelope(msg);
    if (envelope) {
      event._envelope_type = String(envelope.type ?? '');
      event._suite = String(envelope.suite ?? '');
      if (this._isV2EncryptedEnvelopePayload(envelope)) {
        this._attachV2EnvelopeMetadata(event, this._v2E2eeMeta(envelope));
      }
    }
    return event;
  }

  private async _decryptEncryptedPushPayload(msg: JsonObject, group: boolean): Promise<JsonObject | null> {
    const envelope = this._encryptedPushEnvelope(msg);
    if (!this._isV2EncryptedEnvelopePayload(envelope)) return null;
    const aad = isJsonObject(envelope.aad as JsonValue | object | null | undefined) ? envelope.aad as JsonObject : {};
    const fromAid = String(msg.from_aid ?? msg.from ?? msg.sender_aid ?? aad.from ?? '').trim();
    const plaintext = await this._decryptV2EnvelopeForThought({ envelope, fromAid });
    if (!plaintext) return null;
    const e2ee = this._v2E2eeMeta(envelope);
    const result: JsonObject = {
      message_id: String(msg.message_id ?? ''),
      from: fromAid,
      seq: msg.seq as JsonValue,
      timestamp: (msg.t_server ?? msg.timestamp) as JsonValue,
      payload: plaintext as JsonValue,
      encrypted: true,
      e2ee,
    };
    result.direction = fromAid && fromAid === this._aid ? 'outbound_sync' : 'inbound';
    if (msg.t_server !== undefined) result.t_server = msg.t_server as JsonValue;
    if (msg.device_id !== undefined) result.device_id = msg.device_id as JsonValue;
    if (msg.slot_id !== undefined) result.slot_id = msg.slot_id as JsonValue;
    if (group) {
      result.group_id = (msg.group_id ?? aad.group_id ?? envelope.group_id) as JsonValue;
    } else {
      result.to = (msg.to ?? this._aid ?? '') as JsonValue;
    }
    this._attachV2EnvelopeMetadata(result, e2ee);
    this._logMessageDebug('decrypt-ok', 'push.encrypted', group ? 'group.message_created' : 'message.received', result);
    return result;
  }

  private async _publishEncryptedPushAsUndecryptable(
    event: string,
    ns: string,
    seq: unknown,
    msg: JsonObject,
    group: boolean,
  ): Promise<boolean> {
    const safeEvent = this._safeUndecryptablePushEvent(msg, group);
    this._logMessageDebug('decrypt-fail', 'push.encrypted', event, safeEvent);
    if (ns) {
      return await this._publishOrderedMessage(event, ns, seq, safeEvent);
    }
    const published = this._publishAppEvent(event, safeEvent, 'push');
    if (isPromiseLike(published)) await published;
    return true;
  }

  private async _publishEncryptedPushMessage(
    normalEvent: string,
    undecryptableEvent: string,
    ns: string,
    seq: unknown,
    msg: JsonObject,
    group: boolean,
  ): Promise<boolean> {
    const decrypted = await this._decryptEncryptedPushPayload(msg, group);
    if (decrypted) {
      if (ns) return await this._publishOrderedMessage(normalEvent, ns, seq, decrypted);
      const published = this._publishAppEvent(normalEvent, decrypted, 'push');
      if (isPromiseLike(published)) await published;
      return true;
    }
    return await this._publishEncryptedPushAsUndecryptable(undecryptableEvent, ns, seq, msg, group);
  }

  private _metadataWithoutAuth(value: unknown): JsonObject | null {
    const candidate = value as JsonValue | object | null | undefined;
    if (!isJsonObject(candidate)) return null;
    const body: JsonObject = {};
    for (const [key, item] of Object.entries(candidate)) {
      if (key !== '_auth') body[key] = item as JsonValue;
    }
    return body;
  }

  private async _putMessageThoughtEncryptedV2(params: RpcParams): Promise<RpcResult> {
    const toAid = String(params.to ?? '').trim();
    this._validateMessageRecipient(toAid);
    const payload = isJsonObject(params.payload) ? params.payload : null;
    if (!toAid) throw new ValidationError('message.thought.put requires to');
    if (payload === null) throw new ValidationError('message.thought.put payload must be an object when encrypt=true');
    const thoughtId = String(params.thought_id ?? '').trim() || `mt-${crypto.randomUUID()}`;
    const timestamp = Number(params.timestamp ?? Date.now());
    const protectedHeaders = this._protectedHeadersFromParams(params);
    this._logMessageDebug('thought-send-plaintext', 'message.thought.put.v2', 'message.thought.put', {
      to: toAid,
      thought_id: thoughtId,
      timestamp,
      payload,
    }, { payloadOverride: payload });

    const attempt = async (useCache: boolean): Promise<RpcResult> => {
      this._clientLog.debug(`message.thought.put attempt: to=${toAid}, thought_id=${thoughtId}, use_cache=${useCache}`);
      const context = isJsonObject(params.context) ? params.context : undefined;
      const envelope = await this._buildV2P2PEnvelope({
        to: toAid,
        payload,
        messageId: thoughtId,
        timestamp,
        useCache,
        protectedHeaders,
        context,
      });
      const sendParams: RpcParams = {
        to: toAid,
        payload: envelope as JsonObject,
        encrypted: true,
        thought_id: thoughtId,
        timestamp,
      };
      if ('context' in params) sendParams.context = params.context;
      this._signClientOperation('message.thought.put', sendParams);
      this._logMessageDebug('thought-send-envelope', 'message.thought.put.v2', 'message.thought.put', sendParams, {
        payloadOverride: envelope,
        extra: { to: toAid, thought_id: thoughtId, use_cache: useCache },
      });
      const result = await this._transport.call('message.thought.put', sendParams);
      this._clientLog.debug(`message.thought.put ok: to=${toAid}, thought_id=${thoughtId}, use_cache=${useCache}`);
      return result;
    };

    try {
      return await attempt(true);
    } catch (exc) {
      const excCode = Number((exc as { code?: unknown })?.code);
      if (AUNClient.V2_RETRYABLE_CODES.has(excCode)) {
        this._clientLog.debug(`V2 P2P thought put speculative rejected (code=${String(excCode)}), refreshing bootstrap`);
        this._v2BootstrapCache.delete(toAid);
        return await attempt(false);
      }
      throw exc;
    }
  }

  private async _putGroupThoughtEncryptedV2(params: RpcParams): Promise<RpcResult> {
    const groupId = String(params.group_id ?? '').trim();
    const payload = isJsonObject(params.payload) ? params.payload : null;
    if (!groupId) throw new ValidationError("group.thought.put requires 'group_id'");
    if (payload === null) throw new ValidationError('group.thought.put payload must be an object when encrypt=true');
    const thoughtId = String(params.thought_id ?? '').trim() || `gt-${crypto.randomUUID()}`;
    const timestamp = Number(params.timestamp ?? Date.now());
    const protectedHeaders = this._protectedHeadersFromParams(params);
    this._logMessageDebug('thought-send-plaintext', 'group.thought.put.v2', 'group.thought.put', {
      group_id: groupId,
      thought_id: thoughtId,
      timestamp,
      payload,
    }, { payloadOverride: payload });

    const attempt = async (useCache: boolean): Promise<RpcResult> => {
      this._clientLog.debug(`group.thought.put attempt: group=${groupId}, thought_id=${thoughtId}, use_cache=${useCache}`);
      const context = isJsonObject(params.context) ? params.context : undefined;
      const envelope = await this._buildV2GroupEnvelope({
        groupId,
        payload,
        messageId: thoughtId,
        timestamp,
        useCache,
        protectedHeaders,
        context,
      });
      const sendParams: RpcParams = {
        group_id: groupId,
        payload: envelope as JsonObject,
        encrypted: true,
        thought_id: thoughtId,
        timestamp,
      };
      if ('context' in params) sendParams.context = params.context;
      this._signClientOperation('group.thought.put', sendParams);
      this._logMessageDebug('thought-send-envelope', 'group.thought.put.v2', 'group.thought.put', sendParams, {
        payloadOverride: envelope,
        extra: { group_id: groupId, thought_id: thoughtId, use_cache: useCache },
      });
      const result = await this._transport.call('group.thought.put', sendParams);
      this._clientLog.debug(`group.thought.put ok: group=${groupId}, thought_id=${thoughtId}, use_cache=${useCache}`);
      return result;
    };

    try {
      return await attempt(true);
    } catch (exc) {
      const excCode = Number((exc as { code?: unknown })?.code);
      if (AUNClient.V2_RETRYABLE_CODES.has(excCode)) {
        this._clientLog.debug(`V2 group thought put speculative rejected (code=${String(excCode)}), refreshing bootstrap`);
        this._v2BootstrapCache.delete(`group:${groupId}`);
        return await attempt(false);
      }
      throw exc;
    }
  }

  /** 解密 thought 中直接透传的 V2 envelope。 */
  private async _decryptV2EnvelopeForThought(opts: {
    envelope: Record<string, unknown>;
    fromAid: string;
  }): Promise<Record<string, unknown> | null> {
    const session = this._v2Session;
    if (!session) return null;
    const envelope = opts.envelope;
    let spkId = '';
    let recipientKeySource = '';
    if (Array.isArray(envelope.recipients)) {
      for (const row of envelope.recipients) {
        if (!Array.isArray(row) || row.length < 6) continue;
        if (String(row[0] ?? '') === this._aid
          && (String(row[1] ?? '') === this._deviceId || String(row[1] ?? '') === '')) {
          spkId = String(row[5] ?? '');
          recipientKeySource = String(row[3] ?? '');
          break;
        }
      }
    } else if (isJsonObject(envelope.recipient as JsonValue | object | null | undefined)) {
      const recipient = envelope.recipient as JsonObject;
      spkId = String(recipient.spk_id ?? '');
      recipientKeySource = String(recipient.key_source ?? '');
    }
    const aad = isJsonObject(envelope.aad as JsonValue | object | null | undefined) ? envelope.aad as JsonObject : {};
    const groupIdForKeys = String(aad.group_id ?? envelope.group_id ?? '').trim();
    const fromAid = String(opts.fromAid || aad.from || '').trim();
    const senderDeviceId = String(aad.from_device ?? '');
    this._clientLog.debug(`V2 thought decrypt start: from=${fromAid}, sender_device=${senderDeviceId}, group=${groupIdForKeys || '<p2p>'}, spk_id=${spkId || '<empty>'}, key_source=${recipientKeySource || '<empty>'}, type=${String(envelope.type ?? '')}`);
    // group_id 只表示群上下文；group lookup 内部按 group SPK -> P2P device SPK -> IK fallback。
    let ikPriv: Uint8Array;
    let spkPriv: Uint8Array | undefined;
    try {
      if (groupIdForKeys) {
        const keys = session.getGroupDecryptKeys(groupIdForKeys, spkId);
        ikPriv = keys.ikPriv;
        spkPriv = keys.spkPriv ?? undefined;
      } else {
        const keys = session.getDecryptKeys(spkId);
        ikPriv = keys.ikPriv;
        spkPriv = keys.spkPriv;
      }
    } catch (exc) {
      this._clientLog.warn(`V2 thought decrypt: SPK lookup failed from=${fromAid}, group=${groupIdForKeys || '<p2p>'}, spk_id=${spkId || '<empty>'}: ${formatCaughtError(exc)}`);
      return null;
    }
    const senderPubDer = await this._getV2SenderPubDer(fromAid, senderDeviceId);
    if (!senderPubDer) {
      this._clientLog.warn(`V2 thought decrypt: no sender IK for ${fromAid} device=${senderDeviceId}`);
      this._scheduleV2SenderIKFetch(fromAid, senderDeviceId, groupIdForKeys);
      return null;
    }
    try {
      const plain = decryptMessage(
        envelope,
        this._aid ?? '',
        this._deviceId,
        ikPriv,
        spkPriv,
        senderPubDer,
      );
      this._clientLog.debug(`V2 thought decrypt ok: from=${fromAid}, sender_device=${senderDeviceId}, group=${groupIdForKeys || '<p2p>'}`);
      return plain;
    } catch (exc) {
      this._clientLog.warn(`V2 thought decrypt failed from=${fromAid}: ${formatCaughtError(exc)}`);
      return null;
    }
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

  private async _v2VerifyStateSignature(groupId: string, bootstrap: Record<string, unknown>): Promise<void> {
    const stateSignature = String(bootstrap.state_signature ?? '');
    const actorAid = String(bootstrap.state_actor_aid ?? '');
    const stateHashSigned = String(bootstrap.state_hash_signed ?? '');
    const membershipSnapshot = String(bootstrap.state_membership_snapshot ?? '');
    const stateVersion = Number(bootstrap.state_version ?? 0) || 0;
    if (stateVersion === 0 || !stateSignature || !actorAid) return;

    try {
      const signPayload = stableStringify({
        group_id: groupId,
        membership_snapshot: membershipSnapshot,
        state_hash: stateHashSigned,
        state_version: stateVersion,
      });
      const sigBytes = Buffer.from(stateSignature, 'base64');
      const cacheKey = crypto.createHash('sha256')
        .update(lengthPrefixedBytesKey(Buffer.from(actorAid, 'utf-8'), Buffer.from(signPayload, 'utf-8'), sigBytes))
        .digest('hex');

      const now = Date.now();
      const cachedExp = this._v2SigCache.get(cacheKey);
      if (cachedExp === undefined || cachedExp <= now) {
        const certPem = await this._fetchPeerCert(actorAid);
        const cert = new crypto.X509Certificate(certPem);
        const ok = crypto.verify('SHA256', Buffer.from(signPayload, 'utf-8'), cert.publicKey, sigBytes);
        if (!ok) {
          throw new E2EEError(`V2 state signature verification failed: group=${groupId} actor=${actorAid}`);
        }
        this._v2SigCache.set(cacheKey, now + AUNClient.V2_SIG_CACHE_TTL_MS);
        if (this._v2SigCache.size > AUNClient.V2_SIG_CACHE_MAX) {
          const stale: string[] = [];
          for (const [key, exp] of this._v2SigCache) {
            if (exp <= now) stale.push(key);
          }
          for (const key of stale) this._v2SigCache.delete(key);
          if (this._v2SigCache.size > AUNClient.V2_SIG_CACHE_MAX) {
            const entries = [...this._v2SigCache.entries()].sort((a, b) => a[1] - b[1]);
            const evictCount = Math.floor(AUNClient.V2_SIG_CACHE_MAX / 4);
            for (let i = 0; i < evictCount && i < entries.length; i++) {
              this._v2SigCache.delete(entries[i][0]);
            }
          }
        }
      }

      try {
        if (membershipSnapshot.startsWith('[')) {
          const signedSnapshot = JSON.parse(membershipSnapshot);
          if (Array.isArray(signedSnapshot)) {
            const signedMembers = new Set(signedSnapshot.map((item) => String(item)));
            const serverMembers = Array.isArray(bootstrap.member_aids)
              ? bootstrap.member_aids.map((item) => String(item))
              : [];
            const extra = serverMembers.filter((aid) => !signedMembers.has(aid));
            if (extra.length > 0) {
              let mode = '';
              try {
                const req = await this.call('group.get_join_requirements', { group_id: groupId });
                mode = isJsonObject(req) ? String(req.mode ?? '') : '';
              } catch {
                mode = '';
              }
              if (!['open', 'invite_code', 'invite_only'].includes(mode)) {
                await this._dispatcher.publish('group.v2.state_tampered', {
                  group_id: groupId,
                  pending_extra: extra.sort(),
                  mode,
                });
              }
            }
          }
        }
      } catch {
        // snapshot 解析失败不阻断已完成的签名验证。
      }
    } catch (exc) {
      if (exc instanceof E2EEError) throw exc;
      throw new E2EEError(`V2 state signature verification failed: ${formatCaughtError(exc)}`);
    }
  }

  private async _v2CheckFork(groupId: string, serverChain: string): Promise<void> {
    if (!serverChain) return;
    try {
      const local = this._v2StateChains.get(groupId);
      if (!local) {
        this._v2StateChains.set(groupId, [0, serverChain]);
        return;
      }
      const [localSv, localChain] = local;
      if (localChain === serverChain) return;
      try {
        const stateResp = await this.call('group.get_state', { group_id: groupId });
        if (isJsonObject(stateResp)) {
          const serverSv = Number(stateResp.state_version ?? 0);
          if (serverSv > localSv) {
            this._v2StateChains.set(groupId, [serverSv, serverChain]);
            return;
          }
          if (serverSv < localSv) {
            this._clientLog.warn(`V2 state chain rollback detected: group=${groupId} server_sv=${serverSv} local_sv=${localSv}`);
          }
        }
      } catch {
        // get_state 失败时继续发布 fork 告警。
      }
      this._clientLog.warn(`V2 state chain fork detected: group=${groupId} local_chain=${localChain.slice(0, 16)}... server_chain=${serverChain.slice(0, 16)}...`);
      await this._dispatcher.publish('group.v2.fork_detected', {
        group_id: groupId,
        local_chain: localChain,
        server_chain: serverChain,
      });
    } catch (exc) {
      this._clientLog.debug(`V2 fork check failed (non-fatal): ${formatCaughtError(exc)}`);
    }
  }

  private _v2MaybeTriggerAutoPropose(groupId: string): void {
    const now = Date.now();
    const last = this._v2LazyProposeTriggered.get(groupId) ?? 0;
    if (now - last < 10000) return;
    this._v2LazyProposeTriggered.set(groupId, now);
    this._safeAsync(this._v2AutoProposeState(groupId, { leaderDelay: true }));
  }

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

    let resolveTask: () => void;
    let rejectTask: (error: unknown) => void;
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
        resolveTask!();
      } catch (exc) {
        rejectTask!(exc);
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

  private _v2LeaderDelayMs(input: string): number {
    let h = 2166136261;
    for (let i = 0; i < input.length; i++) {
      h ^= input.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return 2000 + ((h >>> 0) % 4000);
  }

  private async _v2AutoProposeLeaderDelay(groupId: string): Promise<boolean> {
    try {
      const membersResp = await this.call('group.get_online_members', { group_id: groupId });
      const members = isJsonObject(membersResp)
        ? (Array.isArray(membersResp.members) ? membersResp.members
          : Array.isArray(membersResp.items) ? membersResp.items
            : Array.isArray(membersResp.online_members) ? membersResp.online_members : [])
        : [];
      if (!Array.isArray(members)) return true;

      const myAid = this._aid ?? '';
      let myRole = '';
      const onlineAdminAids = new Set<string>();
      for (const item of members) {
        if (!isJsonObject(item)) continue;
        const aid = String(item.aid ?? '').trim();
        const role = String(item.role ?? '').trim();
        if (!aid) continue;
        if ('online' in item && !Boolean(item.online)) continue;
        if (role === 'owner' || role === 'admin') onlineAdminAids.add(aid);
        if (aid === myAid) myRole = role;
      }
      if (myRole !== 'owner' && myRole !== 'admin') return false;

      const bootstrapResp = await this.call('group.v2.bootstrap', {
        group_id: groupId,
        e2ee_wrap_capabilities: v2WrapCapabilities(),
      });
      const devices = isJsonObject(bootstrapResp) && Array.isArray(bootstrapResp.devices)
        ? bootstrapResp.devices.filter(isJsonObject) as JsonObject[]
        : [];
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

      const delayMs = this._v2LeaderDelayMs(lengthPrefixedTextKey(groupId, myKey));
      this._clientLog.debug(`V2 auto propose non-leader delay: group=${groupId} leader=${leader} self=${myKey} delay_ms=${delayMs}`);
      await this._sleep(delayMs);
      return true;
    } catch (exc) {
      this._clientLog.debug(`V2 auto propose leader check failed, fallback immediate: group=${groupId} err=${formatCaughtError(exc)}`);
      return true;
    }
  }

  private _v2VerifyCommittedStateBase(groupId: string, stateResp: JsonObject): boolean {
    const currentSv = Number(stateResp.state_version ?? 0) || 0;
    if (currentSv <= 0) return true;
    const currentSh = String(stateResp.state_hash ?? '').trim();
    const membershipSnapshot = String(stateResp.membership_snapshot ?? '').trim();
    if (!currentSh || !membershipSnapshot) {
      this._clientLog.warn(`V2 committed state base incomplete: group=${groupId} sv=${currentSv}`);
      return false;
    }
    try {
      const parsed = JSON.parse(membershipSnapshot) as JsonValue;
      if (!isJsonObject(parsed)) {
        this._clientLog.warn(`V2 committed state base snapshot is not object: group=${groupId} sv=${currentSv}`);
        return false;
      }
      const computed = computeStateCommitment(
        groupId,
        currentSv,
        parsed as Parameters<typeof computeStateCommitment>[2],
      );
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
      const myAid = this._aid ?? '';
      if (!myAid) return;

      const membersResp = await this.call('group.get_members', { group_id: groupId });
      const members = isJsonObject(membersResp)
        ? (Array.isArray(membersResp.members) ? membersResp.members : membersResp.items)
        : [];
      if (!Array.isArray(members)) return;

      let myRole = '';
      const memberAids: string[] = [];
      const adminAids: string[] = [];
      for (const item of members) {
        if (!isJsonObject(item)) continue;
        const aid = String(item.aid ?? '').trim();
        const role = String(item.role ?? '').trim();
        if (!aid) continue;
        memberAids.push(aid);
        if (role === 'owner' || role === 'admin') adminAids.push(aid);
        if (aid === myAid) myRole = role;
      }
      if (myRole !== 'owner' && myRole !== 'admin') return;

      // 前置检查：如果已有 pending proposal，先尝试 confirm 而非重复 propose
      const proposalResp = await this.call('group.v2.get_proposal', { group_id: groupId });
      if (isJsonObject(proposalResp)) {
        const pendingProposal = proposalResp.proposal;
        if (isJsonObject(pendingProposal) && String(pendingProposal.proposal_id ?? '').trim()) {
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

      const bootstrapResp = await this.call('group.v2.bootstrap', {
        group_id: groupId,
        e2ee_wrap_capabilities: v2WrapCapabilities(),
      });
      const allDevices = isJsonObject(bootstrapResp) && Array.isArray(bootstrapResp.devices)
        ? bootstrapResp.devices.filter(isJsonObject) as JsonObject[]
        : [];
      const auditRecipients = isJsonObject(bootstrapResp) && Array.isArray(bootstrapResp.audit_recipients)
        ? bootstrapResp.audit_recipients.filter(isJsonObject) as JsonObject[]
        : [];
      const auditAids = [...new Set(
        auditRecipients.map((item) => String(item.aid ?? '').trim()).filter(Boolean),
      )].sort();

      const membersWithDevices: Record<string, Array<{ device_id: string; ik_fp: string }>> = {};
      for (const aid of memberAids) membersWithDevices[aid] = [];
      for (const dev of allDevices) {
        const aid = String(dev.aid ?? '').trim();
        if (aid in membersWithDevices) {
          membersWithDevices[aid].push({
            device_id: String(dev.device_id ?? ''),
            ik_fp: String(dev.ik_fp ?? ''),
          });
        }
      }
      const statePayload: Record<string, unknown> = {
        members: Object.entries(membersWithDevices).map(([aid, devices]) => ({ aid, devices })),
        audit_aids: auditAids,
        admin_set: { admin_aids: adminAids.sort(), threshold: 1 },
        join_policy_hash: null,
        recovery_quorum: null,
        history_policy: 'recent_7_days',
        wrap_protocol: '3DH',
      };

      const stateResp = await this.call('group.get_state', { group_id: groupId });
      if (!isJsonObject(stateResp)) return;
      if (!this._v2VerifyCommittedStateBase(groupId, stateResp)) return;
      const currentSv = Number(stateResp.state_version ?? 0) || 0;
      const currentSh = String(stateResp.state_hash ?? '');
      const keyEpoch = Number(stateResp.key_epoch ?? 0) || 0;
      const stateHash = computeStateCommitment(groupId, currentSv + 1, statePayload);
      const membershipSnapshot = stableStringify(statePayload);
      const lastMembershipSnapshot = this._v2AutoProposeLastSnapshot.get(groupId);
      if (lastMembershipSnapshot === membershipSnapshot) {
        return;
      }

      // 如果前 state 已经包含同样的 membership_snapshot，说明前一个自动提案已生效，
      // 直接跳过，避免并发触发时重复推进 state_version。
      const currentMembershipSnapshot = String((stateResp as JsonObject).membership_snapshot ?? '');
      if (currentMembershipSnapshot && currentMembershipSnapshot === membershipSnapshot) {
        this._v2AutoProposeLastSnapshot.set(groupId, membershipSnapshot);
        return;
      }

      let signature = '';
      const privateKeyPem = String(this._identity?.private_key_pem ?? '');
      if (privateKeyPem) {
        try {
          const signPayload = stableStringify({
            group_id: groupId,
            membership_snapshot: membershipSnapshot,
            state_hash: stateHash,
            state_version: currentSv + 1,
          });
          const key = crypto.createPrivateKey(privateKeyPem);
          signature = crypto.sign('SHA256', Buffer.from(signPayload, 'utf-8'), key).toString('base64');
        } catch (exc) {
          this._clientLog.debug(`V2 propose_state signature failed: ${formatCaughtError(exc)}`);
        }
      }

      const propose = await this.call('group.v2.propose_state', {
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
      const proposalId = isJsonObject(propose) ? String(propose.proposal_id ?? '').trim() : '';
      if (proposalId) {
        try {
          await this.call('group.v2.confirm_state', { proposal_id: proposalId });
          this._v2AutoProposeLastSnapshot.set(groupId, membershipSnapshot);
        } catch (exc) {
          this._clientLog.debug(`V2 auto confirm_state failed (non-fatal): group=${groupId} err=${formatCaughtError(exc)}`);
        }
      }
    } catch (exc) {
      this._clientLog.debug(`V2 auto propose_state failed (non-fatal): group=${groupId} err=${formatCaughtError(exc)}`);
    }
  }

  private _v2VerifyPendingProposalAgainstBase(groupId: string, proposal: JsonObject, stateResp: JsonObject): boolean {
    if (!this._v2VerifyCommittedStateBase(groupId, stateResp)) return false;
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
      const parsed = JSON.parse(membershipSnapshot) as JsonValue;
      if (!isJsonObject(parsed)) return false;
      const computed = computeStateCommitment(
        groupId,
        proposalSv,
        parsed as Parameters<typeof computeStateCommitment>[2],
      );
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
    const proposalResp = await this.call('group.v2.get_proposal', { group_id: groupId });
    const proposal = isJsonObject(proposalResp) && isJsonObject(proposalResp.proposal)
      ? proposalResp.proposal
      : null;
    const proposalId = proposal ? String(proposal.proposal_id ?? '').trim() : '';
    if (!proposal || !proposalId) return false;

    const stateResp = await this.call('group.get_state', { group_id: groupId });
    if (!isJsonObject(stateResp)) return false;
    const currentSv = Number(stateResp.state_version ?? 0) || 0;
    const proposalSv = Number(proposal.state_version ?? 0) || 0;
    if (proposalSv <= currentSv) {
      this._clientLog.debug(`V2 pending proposal already settled: group=${groupId} current_sv=${currentSv} proposal_sv=${proposalSv}`);
      return false;
    }
    if (!this._v2VerifyPendingProposalAgainstBase(groupId, proposal, stateResp)) return false;

    await this.call('group.v2.confirm_state', { proposal_id: proposalId });
    this._clientLog.info(`V2 confirmed pending proposal: group=${groupId} proposal=${proposalId}`);
    return true;
  }

  private async _v2AutoConfirmPendingProposals(): Promise<void> {
    try {
      const myAid = this._aid ?? '';
      if (!myAid) return;
      const groupsResp = await this.call('group.list_my', {});
      const groups = isJsonObject(groupsResp)
        ? (Array.isArray(groupsResp.groups) ? groupsResp.groups : groupsResp.items)
        : [];
      if (!Array.isArray(groups)) return;
      for (const group of groups) {
        if (!isJsonObject(group)) continue;
        const groupId = String(group.group_id ?? '').trim();
        const myRole = String(group.role ?? group.my_role ?? '').trim();
        if (!groupId || (myRole !== 'owner' && myRole !== 'admin')) continue;
        try {
          const confirmed = await this._v2ConfirmPendingProposal(groupId);
          if (!confirmed) {
            await this._v2AutoProposeState(groupId);
          }
        } catch (exc) {
          this._clientLog.debug(`V2 auto confirm/propose failed (non-fatal): group=${groupId} err=${formatCaughtError(exc)}`);
        }
      }
    } catch (exc) {
      this._clientLog.debug(`V2 auto confirm pending proposals failed (non-fatal): ${formatCaughtError(exc)}`);
    }
  }

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
    // 即使 pushSeq 是脏数据（如服务端 bug 导致的 99999），也只影响"已知上界"，
    // 不会污染下界 contiguousSeq，更不会导致 SDK 把脏数据 ack 回服务端。
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
        const decrypted = await this._decryptV2PushMessage(data);
        if (decrypted) {
          // 解密成功也不能先推进 contiguousSeq；必须等应用层发布返回后再推进和 ACK。
          const published = await this._publishOrderedMessage('message.received', ns, pushSeq, decrypted as EventPayload);
          const newContig = this._seqTracker.getContiguousSeq(ns);
          const needPull = pushSeq > newContig && !published;
          if (newContig !== contigBefore) {
            this._saveSeqTrackerState();
          }
          if (newContig > 0 && newContig !== contigBefore) {
            // ack clamp：永远不发送超过 maxSeenSeq 的 up_to_seq
            const maxSeen = this._seqTracker.getMaxSeenSeq(ns);
            const ackSeq = maxSeen > 0 ? Math.min(newContig, maxSeen) : newContig;
            this.call('message.v2.ack', { up_to_seq: ackSeq, _rpc_background: true })
              .catch(e => this._clientLog.debug(`V2 P2P push-ack failed: ${formatCaughtError(e)}`));
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
        this._clientLog.debug(`_onV2PushNotification: push payload 解密失败, fallback to pull: ${formatCaughtError(exc)}`);
      }
    }

    // ── 不带 payload 或解密失败：触发 pull ──
    // 纯通知只表示服务端已有 pushSeq 这条消息，内容还没有进入本地，不能先推进 contiguousSeq。
    // 后续 pull 必须从当前 contiguousSeq 开始，否则会跳过 pushSeq 本身。
    if (pushSeq > 0 && ns) {
      this._clientLog.debug(
        `_onV2PushNotification: 纯通知 push_seq=${pushSeq} > contiguous_seq=${contigBefore}, 触发 pull(after_seq=${contigBefore})`
      );
    }
    if (!ns) return;
    void this._tryRunBackgroundPull(ns, async () => {
      const operationBefore = this._seqTracker.getContiguousSeq(ns);
      const dedupKey = `p2p_pull:${ns}`;
      if (this._gapFillDone.has(dedupKey)) {
        this._recordPendingP2pPull(ns, pushSeq);
        return 0;
      }
      this._gapFillDone.set(dedupKey, Date.now());
      try {
        const pulled = await this._pullV2(0, 50, { gateLocked: true });
        const newContig = this._seqTracker.getContiguousSeq(ns);
        this._clientLog.debug(
          `_onV2PushNotification pull done: contiguous_seq=${contigBefore}->${newContig} (push_seq=${pushSeq || 'null'})`
        );
        if (newContig <= operationBefore) return 0;
        return pulled.length;
      } finally {
        this._gapFillDone.delete(dedupKey);
      }
    }, true, () => this._recordPendingP2pPull(ns, pushSeq)).catch((exc) => {
      const newContig = this._seqTracker.getContiguousSeq(ns);
      this._clientLog.warn(
        `V2 push auto-pull failed: contiguous_seq=${contigBefore}->${newContig} err=${formatCaughtError(exc)}`
      );
    });
  }

  private async _onV2StateProposed(data: EventPayload): Promise<void> {
    if (!isJsonObject(data) || !this._v2Session) return;
    const rawGroupId = String(data.group_id ?? '').trim();
    const groupId = normalizeGroupId(rawGroupId) || rawGroupId;
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
    const rawGroupId = String(data.group_id ?? '').trim();
    const groupId = normalizeGroupId(rawGroupId) || rawGroupId;
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
    const rawGroupId = String(data.group_id ?? '').trim();
    const groupId = normalizeGroupId(rawGroupId) || rawGroupId;
    if (groupId) {
      this._v2BootstrapCache.delete(`group:${groupId}`);
      this._v2AutoProposeLastSnapshot.delete(groupId);
    }
    await this._dispatcher.publish('group.v2.state_confirmed', data);
  }

  private async _onRawGroupV2MessageCreated(data: EventPayload): Promise<void> {
    if (!isJsonObject(data) || !this._v2Session) {
      this._clientLog.debug(`_onRawGroupV2MessageCreated skipped: is_object=${String(isJsonObject(data))}, has_v2_session=${String(!!this._v2Session)}`);
      return;
    }
    this._logMessageDebug('server-push', '_raw.group.v2.message_created', 'group.message_created', data);
    const rawGroupId = String(data.group_id ?? '').trim();
    const groupId = normalizeGroupId(rawGroupId) || rawGroupId;
    const seq = Number(data.seq ?? 0);
    if (!groupId || !Number.isFinite(seq) || seq <= 0) {
      this._clientLog.debug(`_onRawGroupV2MessageCreated skipped: group=${groupId || '<empty>'}, seq=${String(data.seq ?? '')}`);
      return;
    }
    const ns = `group:${groupId}`;
    // Push 修上界：先更新 maxSeenSeq
    this._seqTracker.updateMaxSeen(ns, seq);
    const contigBefore = this._seqTracker.getContiguousSeq(ns);
    this._clientLog.debug(`_onRawGroupV2MessageCreated enter: group=${groupId}, seq=${seq}, contiguous=${contigBefore}, max_seen=${this._seqTracker.getMaxSeenSeq(ns)}`);
    if (contigBefore === seq) {
      this._clientLog.debug(
        `_onRawGroupV2MessageCreated duplicate push already covered: group=${groupId} seq=${seq}`,
      );
      return;
    }
    const afterSeq = this._repairPushContiguousBound(
      ns,
      seq,
      false,
      '_raw.group.v2.message_created',
    );
    const dedupKey = `v2_group_push:${groupId}:${afterSeq}`;
    void this._tryRunBackgroundPull(ns, async () => {
      const pullAfterSeq = this._seqTracker.getContiguousSeq(ns);
      if (this._gapFillDone.has(dedupKey)) {
        this._clientLog.debug(`_onRawGroupV2MessageCreated skipped duplicate in-flight pull: group=${groupId}, dedup=${dedupKey}`);
        return 0;
      }
      this._gapFillDone.set(dedupKey, Date.now());
      try {
        this._clientLog.debug(`_onRawGroupV2MessageCreated auto-pull start: group=${groupId}, after_seq=${pullAfterSeq}, push_seq=${seq}`);
        const pulled = await this._pullGroupV2(groupId, pullAfterSeq, 50, { gateLocked: true });
        const newContig = this._seqTracker.getContiguousSeq(ns);
        this._clientLog.debug(`_onRawGroupV2MessageCreated auto-pull done: group=${groupId}, after_seq=${pullAfterSeq}, push_seq=${seq}, contiguous=${newContig}`);
        if (newContig <= pullAfterSeq) return 0;
        return pulled.length;
      } finally {
        this._gapFillDone.delete(dedupKey);
      }
    }, true).catch((exc) => {
      this._clientLog.warn(`V2 group push auto-pull failed: group=${groupId} err=${formatCaughtError(exc)}`);
    });
  }

  /** Push 通知带 payload 时的就地解密（复用 _decryptV2Message） */
  private async _decryptV2PushMessage(data: EventPayload): Promise<Record<string, unknown> | null> {
    if (!isJsonObject(data)) return null;
    return await this._decryptV2Message(data as Record<string, unknown>);
  }

  private async _onV2EpochRotated(data: EventPayload): Promise<void> {
    if (!isJsonObject(data)) return;
    const groupId = String(data.group_id ?? '').trim();
    if (!groupId) return;
    this._v2BootstrapCache.delete(`group:${groupId}`);
    if (!this._v2Session) return;
    try {
      await this._v2Session.rotateSPK(this._v2CallFn());
      this._clientLog.info(`SPK rotated after V2 epoch change: group=${groupId} epoch=${String(data.epoch ?? '')}`);
    } catch (exc) {
      this._clientLog.debug(`SPK rotation after V2 epoch change failed (non-fatal): ${formatCaughtError(exc)}`);
    }
  }

  /** 按当前 AID 发现 Gateway；用于 authenticate()/connect() 的新入口。 */
  private async _resolveGatewayForAid(aid: string): Promise<string> {
    const resolvedAid = String(aid ?? this._aid ?? '').trim();
    if (!resolvedAid) {
      throw new StateError('gateway discovery requires a loaded AID');
    }
    if (this._gatewayUrl) return this._gatewayUrl;

    try {
      const loadMetadata = (this._keystore as KeyStore & {
        loadMetadata?: (aid: string) => Record<string, unknown> | null;
      }).loadMetadata;
      const cachedGateway = typeof loadMetadata === 'function'
        ? String(loadMetadata.call(this._keystore, resolvedAid)?.gateway_url ?? '').trim()
        : '';
      if (cachedGateway) {
        this._gatewayUrl = cachedGateway;
        return cachedGateway;
      }
    } catch {
      // 缓存读取失败不影响发现流程。
    }

    const dotIdx = resolvedAid.indexOf('.');
    const issuerDomain = dotIdx >= 0 ? resolvedAid.slice(dotIdx + 1) : resolvedAid;
    const portSuffix = this._configModel.discoveryPort ? `:${this._configModel.discoveryPort}` : '';
    const aidUrl = `https://${resolvedAid}${portSuffix}/.well-known/aun-gateway`;
    const gatewayDomainUrl = `https://gateway.${issuerDomain}${portSuffix}/.well-known/aun-gateway`;
    const candidates = this._configModel.verifySsl ? [aidUrl, gatewayDomainUrl] : [gatewayDomainUrl, aidUrl];
    let lastErr: unknown = null;
    for (const url of candidates) {
      try {
        const gateway = await this._discovery.discover(url);
        this._gatewayUrl = gateway;
        try {
          const saveMetadata = (this._keystore as KeyStore & {
            saveMetadata?: (aid: string, metadata: Record<string, unknown>) => void;
          }).saveMetadata;
          if (typeof saveMetadata === 'function') {
            saveMetadata.call(this._keystore, resolvedAid, { gateway_url: gateway, gateway_cached_at: Date.now() });
          }
        } catch {
          // 缓存写入失败不影响连接。
        }
        return gateway;
      } catch (err) {
        lastErr = err;
        this._clientLog.warn(`gateway discovery failed: aid=${resolvedAid} url=${url} err=${formatCaughtError(err)}`);
      }
    }
    throw lastErr instanceof Error ? lastErr : new ConnectionError(`gateway discovery failed for ${resolvedAid}`);
  }

  /** 从参数中解析 Gateway URL */
  private _resolveGateway(params: ConnectParams): string {
    const gateways = this._resolveGateways(params);
    return gateways[0];
  }

  /** 从参数中解析所有 Gateway URL（支持 string 或 string[]） */
  private _resolveGateways(params: ConnectParams): string[] {
    const topology = params.topology;
    if (isJsonObject(topology)) {
      const topo = topology;
      const mode = String(topo.mode ?? 'gateway');
      if (mode === 'peer') {
        throw new ValidationError('peer topology is not implemented in the TypeScript SDK');
      }
      if (mode === 'relay') {
        throw new ValidationError('relay topology is not implemented in the TypeScript SDK');
      }
    }
    const gw = params.gateway ?? (params as any).gateways;
    if (Array.isArray(gw)) {
      const urls = gw.map(g => String(g ?? '')).filter(u => u.length > 0);
      if (urls.length > 0) return urls;
    }
    if (typeof gw === 'string' && gw) {
      return [gw];
    }
    throw new StateError('missing gateway in connect params');
  }

  /** 连接后同步身份信息 */
  private _syncIdentityAfterConnect(accessToken: string): void {
    const identity = this._auth.loadIdentityOrNone(this._aid ?? undefined);
    if (identity === null) {
      this._identity = null;
      return;
    }
    identity.access_token = accessToken;
    this._identity = identity;
    this._aid = String(identity.aid ?? this._aid ?? '');
    if (this._aid) this._logger.bindAid(this._aid);
    const persistIdentity = (this._auth as any)._persistIdentity as ((value: IdentityRecord) => void) | undefined;
    if (typeof persistIdentity === 'function') {
      persistIdentity.call(this._auth, identity);
      return;
    }
    this._keystore.saveIdentity(String(identity.aid), identity);
  }

  // ── 内部：参数处理 ────────────────────────────────────────

  /** 规范化连接参数 */
  private _normalizeConnectParams(params: RpcParams, opts: { requireAccessToken?: boolean } = {}): ConnectParams {
    const request: ConnectParams = { ...params };
    const accessToken = String(request.access_token ?? '');
    if (!accessToken && opts.requireAccessToken === true) {
      throw new StateError('connect requires non-empty access_token');
    }
    const gateway = String(request.gateway ?? this._gatewayUrl ?? '');
    if (!gateway) throw new StateError('connect requires non-empty gateway');
    if (accessToken) request.access_token = accessToken;
    else delete request.access_token;
    request.gateway = gateway;
    request.device_id = this._deviceId;
    request.slot_id = normalizeInstanceId(request.slot_id ?? this._slotId, 'slot_id', { allowEmpty: true });
    let deliveryModeRaw: JsonValue | object | undefined = request.delivery_mode;
    if (deliveryModeRaw == null) {
      deliveryModeRaw = { ...this._defaultConnectDeliveryMode };
    } else if (!isJsonObject(deliveryModeRaw)) {
      deliveryModeRaw = { mode: deliveryModeRaw };
    } else {
      deliveryModeRaw = { ...deliveryModeRaw };
    }
    if ('queue_routing' in request) {
      (deliveryModeRaw as JsonObject).routing = request.queue_routing;
    }
    if ('affinity_ttl_ms' in request) {
      (deliveryModeRaw as JsonObject).affinity_ttl_ms = request.affinity_ttl_ms;
    }
    request.delivery_mode = normalizeDeliveryModeConfig(deliveryModeRaw);
    if (request.topology != null && !isJsonObject(request.topology)) {
      throw new ValidationError('topology must be a dict');
    }
    if ('retry' in request && request.retry != null && !isJsonObject(request.retry)) {
      throw new ValidationError('retry must be a dict');
    }
    if ('timeouts' in request && request.timeouts != null && !isJsonObject(request.timeouts)) {
      throw new ValidationError('timeouts must be a dict');
    }
    // 长短连接参数校验
    const connectionKind = String(request.connection_kind ?? 'long');
    if (connectionKind !== 'long' && connectionKind !== 'short') {
      throw new ValidationError(`connection_kind must be "long" or "short", got "${connectionKind}"`);
    }
    request.connection_kind = connectionKind;
    const shortTtlMs = Number(request.short_ttl_ms ?? 0);
    if (!Number.isFinite(shortTtlMs) || shortTtlMs < 0 || Math.floor(shortTtlMs) !== shortTtlMs) {
      throw new ValidationError('short_ttl_ms must be a non-negative integer');
    }
    request.short_ttl_ms = connectionKind === 'short' ? shortTtlMs : 0;
    return request;
  }

  /** 从参数构建会话选项 */
  private _buildSessionOptions(params: ConnectParams): SessionOptions {
    const connectionKind = String(params.connection_kind ?? 'long');
    const options: SessionOptions = {
      auto_reconnect: DEFAULT_SESSION_OPTIONS.auto_reconnect,
      heartbeat_interval: DEFAULT_SESSION_OPTIONS.heartbeat_interval,
      token_refresh_before: DEFAULT_SESSION_OPTIONS.token_refresh_before,
      retry: { ...DEFAULT_SESSION_OPTIONS.retry },
      timeouts: { ...DEFAULT_SESSION_OPTIONS.timeouts },
      connection_kind: connectionKind,
    };
    if ('auto_reconnect' in params) options.auto_reconnect = Boolean(params.auto_reconnect);
    if ('heartbeat_interval' in params) options.heartbeat_interval = Number(params.heartbeat_interval);
    if ('token_refresh_before' in params) options.token_refresh_before = Number(params.token_refresh_before);
    if ('retry' in params && isJsonObject(params.retry)) {
      Object.assign(options.retry, params.retry);
    }
    if ('timeouts' in params && isJsonObject(params.timeouts)) {
      Object.assign(options.timeouts, params.timeouts);
    }
    return options;
  }

  // ── 内部：后台任务 ────────────────────────────────────────

  /** 启动所有后台任务 */
  private _startBackgroundTasks(): void {
    // 短连接不启动 heartbeat 与 token 刷新（生命周期短，不需要长期会话维护）；
    // auto_reconnect 仍允许，由 _sessionOptions.auto_reconnect 决定
    if (this._sessionOptions.connection_kind !== 'short') {
      this._startHeartbeatTask();
      this._startTokenRefreshTask();
    }
    this._startV2MaintenanceTasks();
  }

  /** 停止所有后台任务 */
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

  /** 启动心跳任务 */
  private _startHeartbeatTask(): void {
    if (this._heartbeatTimer !== null) return;
    const interval = clampHeartbeatInterval(
      this._sessionOptions.heartbeat_interval ?? DEFAULT_SESSION_OPTIONS.heartbeat_interval,
    );
    if (interval <= 0) return;

    // M25: 把连续失败阈值从 3 次收窄到 2 次。既能容忍一次网络抖动/GC 暂停，
    // 又把半开连接的检测延迟从 3 个心跳周期降到 2 个。
    // 真正的 socket 死亡由 ws.on('close') 立即触发 _handleTransportDisconnect，
    // 不依赖此心跳路径。
    let consecutiveFailures = 0;
    const maxFailures = 2;

    this._heartbeatTimer = setInterval(() => {
      if (this._closing || this.state !== ConnectionState.READY) return;
      this._transport.call('meta.ping', {}).then((pong) => {
        consecutiveFailures = 0;
        // 服务端可在 pong 中下发新的 heartbeat_interval（秒，0=关闭）
        if (isJsonObject(pong) && 'heartbeat_interval' in pong) {
          this._applyServerHeartbeatInterval((pong as JsonObject).heartbeat_interval, 'pong');
        }
      }).catch((exc) => {
        consecutiveFailures++;
        this._clientLog.warn(`heartbeat failed (${consecutiveFailures}/${maxFailures}): ${formatCaughtError(exc)}`);
        this._dispatcher.publish('connection.error', { error: formatCaughtError(exc) }).catch(() => {});
        if (consecutiveFailures >= maxFailures) {
          this._clientLog.warn(`${maxFailures} consecutive heartbeat failures, triggering reconnect`);
          this._handleTransportDisconnect(exc instanceof Error ? exc : new Error(String(exc)));
        }
      });
    }, interval * 1000);
    // 允许 Node.js 进程在只剩定时器时退出
    if (this._heartbeatTimer && typeof this._heartbeatTimer === 'object' && 'unref' in this._heartbeatTimer) {
      (this._heartbeatTimer as NodeJS.Timer).unref();
    }
  }

  /** 服务端通过 hello/pong 下发 heartbeat_interval；clamp 后写入 session_options 并按需重启心跳。 */
  private _applyServerHeartbeatInterval(raw: unknown, source: 'auth' | 'pong'): void {
    const newInterval = clampHeartbeatInterval(raw);
    const oldInterval = clampHeartbeatInterval(this._sessionOptions.heartbeat_interval);
    if (newInterval === oldInterval) return;
    this._sessionOptions.heartbeat_interval = newInterval;
    this._clientLog.debug(`heartbeat_interval updated by ${source}: ${oldInterval} -> ${newInterval}`);
    if (this._heartbeatTimer !== null) {
      clearInterval(this._heartbeatTimer);
      this._heartbeatTimer = null;
    }
    if (newInterval > 0 && this.state === ConnectionState.READY && !this._closing) {
      this._startHeartbeatTask();
    }
  }

  /** 启动 token 刷新任务 */
  private _startTokenRefreshTask(): void {
    if (this._tokenRefreshTimer !== null) return;
    const rawLead = Number(this._sessionOptions.token_refresh_before ?? DEFAULT_SESSION_OPTIONS.token_refresh_before);
    const lead = Number.isFinite(rawLead) && rawLead > 0
      ? rawLead
      : DEFAULT_SESSION_OPTIONS.token_refresh_before;

    const scheduleNext = (delayMs = TOKEN_REFRESH_CHECK_INTERVAL_MS): void => {
      if (this._closing) return;
      this._tokenRefreshTimer = setTimeout(async () => {
        if (this._closing) return;
        this._tokenRefreshTimer = null;
        if (this.state !== ConnectionState.READY || !this._gatewayUrl) {
          scheduleNext();
          return;
        }

        let identity = this._identity ?? this._auth.loadIdentityOrNone() ?? null;
        if (identity === null) {
          scheduleNext();
          return;
        }
        this._identity = identity;

        const expiresAt = this._auth.getAccessTokenExpiry(identity);
        if (expiresAt === null) {
          scheduleNext();
          return;
        }
        if ((expiresAt - Date.now() / 1000) > lead) {
          scheduleNext();
          return;
        }

        if (this._closing || this.state !== ConnectionState.READY || !this._gatewayUrl) {
          scheduleNext();
          return;
        }
        try {
          identity = await this._auth.refreshCachedTokens(this._gatewayUrl!, identity!);
          // 刷新期间可能已断线，复检状态，避免写回 stale identity
          if (this.state !== ConnectionState.READY) { scheduleNext(); return; }
          this._identity = identity;
          if (this._sessionParams !== null && identity.access_token) {
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
              this._clientLog.warn(`token refresh failed ${this._tokenRefreshFailures} consecutive times, stopping refresh loop and triggering reconnect`);
              await this._dispatcher.publish('token.refresh_exhausted', {
                aid: this._identity?.aid ?? null,
                consecutive_failures: this._tokenRefreshFailures,
                last_error: String(exc),
              });
              this._tokenRefreshFailures = 0;
              this._handleTransportDisconnect(new Error('token refresh exhausted, triggering reconnect'));
              return;
            }
            this._clientLog.debug(`token refresh failed (${this._tokenRefreshFailures}/3), will retry: ${exc}`);
          } else {
            await this._dispatcher.publish('connection.error', { error: formatCaughtError(exc) });
          }
        }
        scheduleNext();
      }, delayMs);
      this._unrefTimer(this._tokenRefreshTimer);
    };

    scheduleNext(0);
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

  /** 启动 V2 缓存清理后台任务 */
  private _startV2MaintenanceTasks(): void {
    if (this._cacheCleanupTimer === null) {
      this._cacheCleanupTimer = setInterval(() => {
        const nowSec = Date.now() / 1000;
        // 证书缓存
        for (const [k, v] of this._certCache) {
          if (nowSec >= v.refreshAfter) this._certCache.delete(k);
        }
        // 补洞去重：清理超过 5 分钟的旧条目（与 Python 对齐，按时间过期）
        const gapCutoffMs = Date.now() - 300_000;
        for (const [k, ts] of this._gapFillDone) {
          if (ts < gapCutoffMs) this._gapFillDone.delete(k);
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
        // auth gateway 缓存
        this._auth.cleanExpiredCaches();
      }, 3600_000);
      this._unrefTimer(this._cacheCleanupTimer);
    }
  }

  /** 允许 Node.js 进程在只剩定时器时退出 */
  private _unrefTimer(timer: ReturnType<typeof setTimeout> | ReturnType<typeof setInterval> | null): void {
    if (timer && typeof timer === 'object' && 'unref' in timer) {
      (timer as NodeJS.Timer).unref();
    }
  }

  // ── 内部：断线重连 ────────────────────────────────────────

  /** 不重连 close code 集合：认证失败/权限错误/被踢等，重连无意义 */
  private static readonly _NO_RECONNECT_CODES = new Set([4001, 4003, 4008, 4009, 4010, 4011, 4012, 4013, 4014, 4015]);

  /** 处理服务端主动断开通知 event/gateway.disconnect。
   *
   * 服务端可能附带结构化 detail 字段（如配额超限时含 aid/device_id/slot_id/quota_kind/evicted_by）。
   * 透传到应用层可订阅事件 'gateway.disconnect'，方便业务定位被踢原因。
   */
  private async _onGatewayDisconnect(data: any): Promise<void> {
    const payload = (data && typeof data === 'object') ? data : {};
    const code = payload.code;
    const reason = payload.reason ?? '';
    const detail = (payload.detail && typeof payload.detail === 'object' && !Array.isArray(payload.detail))
      ? payload.detail
      : {};
    this._clientLog.warn(
      `server initiated disconnect: code=${code}, reason=${reason}, detail=${JSON.stringify(detail)}`,
    );
    this._serverKicked = true;
    // 缓存最近一次 disconnect 信息，让后续 connection.state(connection_failed) 也能带 detail
    this._lastDisconnectInfo = { code, reason, detail };
    // 透传给应用层订阅者
    try {
      await this._dispatcher.publish('gateway.disconnect', {
        code,
        reason,
        detail,
      });
    } catch (exc) {
      this._clientLog.debug(
        `publish gateway.disconnect failed: ${exc instanceof Error ? exc.message : String(exc)}`,
      );
    }
  }

  /** 传输层断线回调 */
  private async _handleTransportDisconnect(error: Error | null, closeCode?: number): Promise<void> {
    if (this._closing || this.state === ConnectionState.CLOSED) return;
    // 已在重连中则跳过，避免心跳超时和 transport 断线回调重复触发
    if (this._reconnectActive) return;
    this._clientLog.warn(`transport disconnected: closeCode=${closeCode ?? 'none'}, error=${error ? formatCaughtError(error) : 'none'}`);
    this._state = 'standby';
    this._stopBackgroundTasks();
    await this._dispatcher.publish('state_change', { state: this._publicState(this._state), error });

    if (!this._sessionOptions.auto_reconnect) return;
    if (this._reconnectActive) return;
    // 不重连 close code（认证失败/权限错误/被踢等）或服务端通知断开：抑制重连
    if (this._serverKicked || (closeCode !== undefined && AUNClient._NO_RECONNECT_CODES.has(closeCode))) {
      this._state = 'connection_failed';
      const reason = this._serverKicked ? 'server kicked' : `close code ${closeCode}`;
      this._clientLog.warn(`suppressing auto-reconnect: ${reason}`);
      const disconnectInfo = this._lastDisconnectInfo ?? {};
      const eventPayload: Record<string, any> = {
        state: this._publicState(this._state), error, reason,
      };
      // 把服务端附带的结构化 detail（如配额超限信息）也带给应用层
      if (disconnectInfo.detail && Object.keys(disconnectInfo.detail).length > 0) {
        eventPayload.detail = disconnectInfo.detail;
      }
      if (disconnectInfo.code !== undefined && disconnectInfo.code !== null) {
        eventPayload.code = disconnectInfo.code;
      }
      await this._dispatcher.publish('state_change', eventPayload);
      return;
    }
    // 1000 = 正常关闭, 1006 = 网络异常断开（无 close frame），其他 code = 服务端主动关闭
    const serverInitiated = closeCode !== undefined && closeCode !== 1000 && closeCode !== 1006;
    this._startReconnect(serverInitiated);
  }

  /** 启动重连循环（默认无限重试 + 指数退避 + 固定上限抖动，仅在不可重试错误、close() 或 max_attempts 耗尽时终止） */
  private _startReconnect(serverInitiated = false): void {
    if (this._reconnectActive) return;
    this._reconnectActive = true;
    this._reconnectAbort = new AbortController();
    this._clientLog.debug(`reconnect loop started: serverInitiated=${String(serverInitiated)}, aid=${this._aid ?? ''}`);
    this._reconnectLoop(serverInitiated).catch((exc) => {
      this._clientLog.warn(`reconnect loop error: ${formatCaughtError(exc)}`);
    });
  }

  /** 重连循环（for 循环 + AbortController，与 JS/Python 对齐） */
  private async _reconnectLoop(serverInitiated: boolean): Promise<void> {
    const retry = this._sessionOptions.retry;
    const maxBaseDelay = clampReconnectDelayMs(
      Number(retry.max_delay ?? 64.0) * 1000,
      RECONNECT_MAX_BASE_DELAY_MS,
    );
    const maxAttemptsRaw = Number(retry.max_attempts ?? 0);
    const maxAttempts = Number.isFinite(maxAttemptsRaw) && maxAttemptsRaw > 0 ? Math.floor(maxAttemptsRaw) : 0;
    this._retryMaxAttempts = maxAttempts;
    let delay = clampReconnectDelayMs(
      serverInitiated ? 16_000 : Number(retry.initial_delay ?? 1.0) * 1000,
      serverInitiated ? 16_000 : RECONNECT_MIN_BASE_DELAY_MS,
      maxBaseDelay,
    );

    for (let attempt = 1; !this._reconnectAbort?.signal.aborted; attempt++) {
      if (this._closing) break;
      // max_attempts 检查在循环顶部，覆盖所有路径（含 health-fail）
      if (maxAttempts > 0 && attempt > maxAttempts) {
        this._state = 'connection_failed';
        await this._dispatcher.publish('state_change', {
          state: this._publicState(this._state),
          attempt: attempt - 1,
          reason: 'max_attempts_exhausted',
        });
        break;
      }

      this._retryAttempt = attempt;
      this._nextRetryAt = Date.now() + reconnectSleepDelayMs(delay, maxBaseDelay);
      this._state = 'retry_backoff';
      await this._dispatcher.publish('state_change', {
        state: this._publicState(this._state),
        attempt,
        next_retry_at: this._nextRetryAt,
      });

      try {
        // 固定上限抖动：base=[1s, max_base]，delay=base+rand(0..max_base)。
        await this._sleep(Math.max(0, this._nextRetryAt - Date.now()));
        if (this._reconnectAbort?.signal.aborted || this._closing) break;
        this._state = 'reconnecting';
        await this._dispatcher.publish('state_change', {
          state: this._publicState(this._state),
          attempt,
        });

        // 重连前先 GET /health 探测，不健康则跳过本轮
        if (this._gatewayUrl) {
          const healthy = await this._discovery.checkHealth(this._gatewayUrl, 5_000);
          if (!healthy) {
            delay = Math.min(delay * 2, maxBaseDelay);
            continue;
          }
        }
        await this._transport.close();
        if (this._sessionParams === null) {
          throw new StateError('missing connect params for reconnect');
        }
        await this._connectOnce(this._sessionParams, true);
        // 重连成功，退出循环
        this._clientLog.debug(`reconnect success: attempt=${attempt}, aid=${this._aid ?? ''}`);
        this._nextRetryAt = null;
        this._reconnectActive = false;
        this._reconnectAbort = null;
        return;
      } catch (exc) {
        await this._dispatcher.publish('connection.error', {
          error: formatCaughtError(exc),
          attempt,
        });
        if (!AUNClient._shouldRetryReconnect(exc as Error)) {
          this._state = 'connection_failed';
          await this._dispatcher.publish('state_change', {
            state: this._publicState(this._state),
            error: formatCaughtError(exc),
            attempt,
          });
          break;
        }
        delay = Math.min(delay * 2, maxBaseDelay);
      }
    }

    this._reconnectActive = false;
    this._reconnectAbort = null;
  }

  /** 可取消的 sleep */
  private _sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      const timer = setTimeout(resolve, ms);
      this._unrefTimer(timer);
    });
  }

  /** 停止重连 */
  private _stopReconnect(): void {
    if (this._reconnectAbort) {
      this._reconnectAbort.abort();
      this._reconnectAbort = null;
    }
    this._reconnectActive = false;
  }

  // ── Named Group（命名群）高层 API ────────────────────────────

  /**
   * 创建命名群：本地生成 P-256 keypair，调用 group.create 传入 public_key，
   * 服务端签发群 AID 证书，返回后将证书和私钥存入 keystore。
   */
  private async createNamedGroup(groupName: string, opts: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
    const tStart = Date.now();
    this._clientLog.debug(`createNamedGroup enter: groupName=${groupName}`);
    try {
    const cp = new CryptoProvider();
    const identity = cp.generateIdentity();
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
      this._keystore.saveIdentity(groupAid, {
        private_key_pem: identity.private_key_pem,
        public_key: identity.public_key_der_b64,
        curve: 'P-256',
        type: 'group_identity',
      });
      const certPem = String(aidCert.cert ?? '');
      if (certPem) {
        this._keystore.saveCert(groupAid, certPem);
      }
    }
    this._clientLog.debug(`createNamedGroup exit: elapsed=${Date.now() - tStart}ms groupAid=${groupAid}`);
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
    this._clientLog.debug(`bindGroupAid enter: groupId=${groupId}, groupName=${groupName}`);
    try {
    const cp = new CryptoProvider();
    const identity = cp.generateIdentity();
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
      this._keystore.saveIdentity(groupAid, {
        private_key_pem: identity.private_key_pem,
        public_key: identity.public_key_der_b64,
        curve: 'P-256',
        type: 'group_identity',
      });
      const certPem = String(aidCert.cert ?? '');
      if (certPem) {
        this._keystore.saveCert(groupAid, certPem);
      }
    }
    this._clientLog.debug(`bindGroupAid exit: elapsed=${Date.now() - tStart}ms groupAid=${groupAid}`);
    return result;
    } catch (err) {
      this._clientLog.debug(`bindGroupAid exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 判断是否应重试重连 */
  private static _shouldRetryReconnect(error: Error): boolean {
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
    if (error instanceof TimeoutError) return true;
    // 其他网络错误默认重试
    return true;
  }
}

