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
import * as http from 'node:http';
import * as https from 'node:https';
import { URL } from 'node:url';

import { configFromMap, getDeviceId, normalizeSlotId, type AUNConfig } from './config.js';
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
import { LocalTokenStore } from './keystore/local-token-store.js';
import type { TokenStore } from './keystore/index.js';
import { AUNLogger, type ModuleLogger } from './logger.js';
import { normalizeGroupId } from './group-id.js';

import { RPCTransport } from './transport.js';
import { AuthFlow } from './auth.js';
import { AgentMdManager } from './agent-md.js';
import { SeqTracker } from './seq-tracker.js';
import { ClientRuntime } from './client/runtime.js';
import { MessageDeliveryEngine } from './client/delivery.js';
import { IdentityRuntimeManager } from './client/identity.js';
import { LifecycleController } from './client/lifecycle.js';
import { PeerDirectory } from './client/peers.js';
import { RpcPipeline } from './client/rpc-pipeline.js';
import { V2E2EECoordinator } from './client/v2-e2ee.js';
import { GroupStateCoordinator } from './client/group-state.js';
import { V2Session, V2KeyStore, type CallFn } from './v2/session/index.js';
import {
  decryptMessage,
  type Target,
} from './v2/e2ee/index.js';
import { ecdsaVerifyRaw } from './v2/crypto/ecdsa.js';
import {
  isJsonObject,
  type IdentityRecord,
  type JsonObject,
  type JsonValue,
  type RpcParams,
  type RpcResult,
  ConnectionState,
  STATE_TO_PUBLIC,
} from './types.js';
import { AID } from './aid.js';
import { certMatchesFingerprint, normalizeFingerprintHex } from './cert-utils.js';

function isPromiseLike<T = unknown>(value: unknown): value is PromiseLike<T> {
  return Boolean(value && typeof (value as { then?: unknown }).then === 'function');
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

function getV2DeviceId(dev: Record<string, unknown>): { present: boolean; value: string } {
  if (Object.prototype.hasOwnProperty.call(dev, 'device_id')) {
    return { present: true, value: String(dev.device_id ?? '').trim() };
  }
  if (Object.prototype.hasOwnProperty.call(dev, 'owner_device_id')) {
    return { present: true, value: String(dev.owner_device_id ?? '').trim() };
  }
  return { present: false, value: '' };
}

// ── 常量 ──────────────────────────────────────────────────────

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

const RECONNECT_MIN_BASE_DELAY_MS = 1_000;
const RECONNECT_MAX_BASE_DELAY_MS = 64_000;
const TOKEN_REFRESH_CHECK_INTERVAL_MS = 30_000;

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

/** peer 证书缓存 TTL（1 小时） */
const PEER_CERT_CACHE_TTL = 3600;

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

interface V2SenderIKPendingEntry {
  msg: Record<string, unknown>;
  fromAid: string;
  senderDeviceId: string;
  groupId: string;
  createdAt: number;
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
    verifySsl: opts.config().verifySsl,
    discoveryPort: opts.config().discoveryPort,
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
      let identity = opts.identity.get();
      if (!identity || String(identity.aid ?? '') !== target) {
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

      const result = await auth.authenticate(gatewayUrl, { aid: target });
      const token = String(result.access_token ?? '');
      if (!token) throw new StateError('authenticate did not return access_token');
      identity = auth.loadIdentityOrNone(target) ?? {
        ...identity,
        access_token: token,
        refresh_token: String(result.refresh_token ?? identity.refresh_token ?? ''),
        access_token_expires_at: typeof result.expires_at === 'number' ? result.expires_at : identity.access_token_expires_at,
        token_exp: typeof result.expires_at === 'number' ? result.expires_at : identity.token_exp,
        expires_at: typeof result.expires_at === 'number' ? result.expires_at : identity.expires_at,
      };
      opts.identity.set(identity);
      return token;
    },
    peerResolver: async (aid, certFingerprint) => {
      const target = String(aid ?? '').trim();
      const expectedFp = String(certFingerprint ?? '').trim().toLowerCase();
      const current = opts.currentAid();
      if (current?.aid === target) {
        if (!expectedFp || certMatchesFingerprint(current.certPem, expectedFp)) return current;
        throw new StateError(`current AID certificate fingerprint mismatch for ${target}`);
      }
      if (!opts.gateway.get()) {
        try { opts.gateway.set(await opts.gateway.resolve(target)); } catch { /* best effort before cert fetch */ }
      }
      const certPem = String(await opts.fetchPeerCert(target, expectedFp || undefined) ?? '').trim();
      if (!certPem) throw new NotFoundError(`certificate not found for aid: ${target}`);
      return AID._create({
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
  private _tokenStore: TokenStore;

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

  private _agentMdManager!: AgentMdManager;

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
  /** 在线未读 hint 队列：同一 group 只保留最后一条，延迟 drain 降低登录瞬时拉取压力。 */
  private _onlineUnreadHintQueue: Map<string, JsonObject> = new Map();
  private _onlineUnreadHintTimer: ReturnType<typeof setTimeout> | null = null;
  private _onlineUnreadHintDrainActive = false;
  private _onlineUnreadHintInitialDelayMs = 750;
  private _onlineUnreadHintIntervalMs = 50;
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
  private _v2SessionInitInFlight: Promise<void> | null = null;
  private _v2RuntimeGeneration = 0;
  /** V2 bootstrap 缓存：aid/group:id → 设备列表 + 时间戳 */
  private _v2BootstrapCache: Map<string, V2BootstrapEntry> = new Map();
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
  /** 对端 AID 缓存（aid string → AID 对象） */
  private _peerCache = new Map<string, AID>();
  private _reconnectActive = false;
  private _reconnectAbort: AbortController | null = null;
  private _serverKicked = false;
  /** 缓存最近一次 gateway.disconnect 信息（含服务端附带的 detail），用于后续 connection.state 透传 */
  private _lastDisconnectInfo: { code?: any; reason?: string; detail?: Record<string, any> } | null = null;
  private _logger!: AUNLogger;
  private _clientLog!: ModuleLogger;
  private _runtime!: ClientRuntime;
  private _identityRuntime!: IdentityRuntimeManager;
  private _peerDirectory!: PeerDirectory;
  private _lifecycle!: LifecycleController;
  private _rpcPipeline!: RpcPipeline;
  private _delivery!: MessageDeliveryEngine;
  private _v2E2EE!: V2E2EECoordinator;
  private _groupState!: GroupStateCoordinator;

  constructor(aid?: AID) {
    if (aid !== null && aid !== undefined && !isAIDObject(aid)) {
      throw new ValidationError('AUNClient only accepts an AID object or no argument');
    }
    const inputAid = aid ?? null;
    const rawConfig: RpcParams = {};
    if (inputAid) {
      rawConfig.aun_path = inputAid.aunPath;
      rawConfig.verify_ssl = inputAid.verifySsl;
      if (inputAid.rootCaPath) rawConfig.root_ca_path = inputAid.rootCaPath;
      rawConfig.debug = inputAid.debug;
    }
    this._configModel = configFromMap(rawConfig);
    const initAid = (inputAid && inputAid.isPrivateKeyValid()) ? inputAid.aid : null;
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

    const tokenStore = new LocalTokenStore(
      this._configModel.aunPath,
      {
        logger: this._logger.for('aun_core.keystore'),
      },
    );
    this._tokenStore = tokenStore;

    this._slotId = inputAid?.slotId || 'default';
    this._connectDeliveryMode = normalizeDeliveryModeConfig({ mode: 'fanout' });
    this._defaultConnectDeliveryMode = { ...this._connectDeliveryMode };

    this._auth = new AuthFlow({
      tokenStore,
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
    this._agentMdManager = createAgentMdManagerForRuntime({
      config: () => this._configModel,
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
      timeout: 10_000,
      onDisconnect: (err, closeCode) => this._handleTransportDisconnect(err, closeCode),
      verifySsl: this._configModel.verifySsl,
      logger: this._logger.for('aun_core.transport'),
      dnsNet,
    });
    this._transport.setMetaObserver((meta) => this._observeRpcMeta(meta));
    this._runtime = new ClientRuntime(this);
    this._identityRuntime = new IdentityRuntimeManager(this._runtime);
    this._peerDirectory = new PeerDirectory(this._runtime);
    this._lifecycle = new LifecycleController(this._runtime);
    this._rpcPipeline = new RpcPipeline(this._runtime);
    this._delivery = new MessageDeliveryEngine(this._runtime);
    this._v2E2EE = new V2E2EECoordinator(this._runtime);
    this._groupState = new GroupStateCoordinator(this._runtime);

    if (inputAid) {
      // 与 Python 对齐：私钥无效时只用 aunPath 配置，state 保持 no_identity
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

    const rawConfig: RpcParams = {
      aun_path: aid.aunPath,
      verify_ssl: aid.verifySsl,
      debug: aid.debug,
    };
    if (aid.rootCaPath) rawConfig.root_ca_path = aid.rootCaPath;
    const nextConfig = configFromMap(rawConfig);

    try {
      const close = (this._tokenStore as unknown as { close?: () => void }).close;
      if (typeof close === 'function') close.call(this._tokenStore);
    } catch {
      // best-effort cleanup before switching tokenStore roots
    }

    this._configModel = nextConfig;
    this.config.aun_path = nextConfig.aunPath;
    this.config.root_ca_path = nextConfig.rootCaPath;
    this.config.seed_password = nextConfig.seedPassword;
    this._peerCache.clear();
    this._certCache.clear();
    this._gatewayUrl = null;

    this._deviceId = aid.deviceId || getDeviceId(nextConfig.aunPath);
    this._slotId = aid.slotId || 'default';

    const debugFlag = nextConfig.debug;
    this._logger = new AUNLogger({ debug: debugFlag, aunPath: nextConfig.aunPath });
    this._logger.bindDeviceId(this._deviceId);
    this._clientLog = this._logger.for('aun_core.client');

    const dnsNet = new DnsResilientNet({
      verifySsl: nextConfig.verifySsl,
      logger: this._clientLog,
    });
    this._discovery = new GatewayDiscovery({ verifySsl: nextConfig.verifySsl, logger: this._clientLog, net: dnsNet });

    const tokenStore = new LocalTokenStore(
      nextConfig.aunPath,
      {
        logger: this._logger.for('aun_core.keystore'),
      },
    );
    this._tokenStore = tokenStore;
    this._auth = new AuthFlow({
      tokenStore,
      crypto: new CryptoProvider(),
      aid: aid.aid,
      deviceId: this._deviceId,
      slotId: this._slotId,
      rootCaPath: nextConfig.rootCaPath ?? undefined,
      verifySsl: nextConfig.verifySsl,
      logger: this._logger.for('aun_core.auth'),
      net: dnsNet,
    });
    this._agentMdManager = createAgentMdManagerForRuntime({
      config: () => this._configModel,
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
      timeout: 10_000,
      onDisconnect: (err, closeCode) => this._handleTransportDisconnect(err, closeCode),
      verifySsl: nextConfig.verifySsl,
      logger: this._logger.for('aun_core.transport'),
      dnsNet,
    });
    this._transport.setMetaObserver((meta) => this._observeRpcMeta(meta));
  }

  loadIdentity(aid: AID): void {
    this._identityRuntime.loadIdentity(aid);
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

  /** transport 的 meta observer：吸收 gateway 注入的 _meta 字段。失败不影响业务。 */
  private _observeRpcMeta(meta: Record<string, unknown>): void {
    this._agentMdManager.observeRpcMeta(meta, this._aid);
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
    return this._lifecycle.authenticate(options);
  }

  /** 连接到 Gateway；身份来自构造函数或 loadIdentity(aid)，认证由 SDK 内部自动完成。 */
  async connect(opts?: ConnectionOptions): Promise<void> {
    return this._lifecycle.connect(opts);
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
        const closableStore = this._tokenStore as TokenStore & { close?: () => void };
        closableStore.close?.();
        this._state = 'closed';
        this._logger.close();
        this._resetSeqTrackingState();
        this._clientLog.debug(`close exit: elapsed=${Date.now() - tStart}ms (was no_identity/closed)`);
        return;
      }
      await this._transport.close();
      const closableStore = this._tokenStore as TokenStore & { close?: () => void };
      closableStore.close?.();
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
    const preflight = this._rpcPipeline.preflight(method, params);
    const p = preflight.params;
    const rpcBackground = preflight.rpcBackground;
    const runWithRpcPriority = async <T>(operation: () => Promise<T> | T): Promise<T> => {
      if (!rpcBackground) return await operation();
      return await this._withBackgroundRpc(operation);
    };

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
      const hasExplicitAfterSeq = 'after_seq' in p || 'after_message_seq' in p;
      const cursorParams = this._explicitGroupCursorParams(p);
      const ownsCursor = Object.keys(cursorParams).length === 0 || this._groupCursorTargetsCurrentInstance(cursorParams);
      const pullOpts: { gateLocked: boolean; explicitAfterSeq?: boolean; cursorParams?: RpcParams; ownsCursor?: boolean } = { gateLocked: true };
      if (hasExplicitAfterSeq) pullOpts.explicitAfterSeq = true;
      if (Object.keys(cursorParams).length > 0) pullOpts.cursorParams = cursorParams;
      if (!ownsCursor) pullOpts.ownsCursor = false;
      const messages = await runWithRpcPriority(() => this._pullGroupV2(
        String(p.group_id),
        Number(p.after_seq ?? p.after_message_seq ?? 0) || 0,
        Number(p.limit ?? 50) || 50,
        pullOpts,
      ));
      return { messages } as RpcResult;
    }

    if (method === 'group.ack_messages' || method === 'group.v2.ack') {
      if (!String(p.group_id ?? '').trim()) {
        throw new ValidationError('group.ack_messages requires group_id');
      }
      await this._ensureV2SessionReady('group.ack_messages');
      const cursorParams = this._explicitGroupCursorParams(p);
      const ownsCursor = Object.keys(cursorParams).length === 0 || this._groupCursorTargetsCurrentInstance(cursorParams);
      if (method === 'group.ack_messages' && !ownsCursor) {
        return await runWithRpcPriority(() => this._rawGroupAckMessages(p)) as RpcResult;
      }
      return await runWithRpcPriority(() => this._ackGroupV2(
        String(p.group_id),
        Number(p.seq ?? p.msg_seq ?? p.up_to_seq ?? 0) || undefined,
      )) as RpcResult;
    }

    if (method === 'message.pull') {
      delete p._skip_auto_ack;
      delete p.skip_auto_ack;
    }
    delete (p as Record<string, unknown>)._group_cursor_params;

    // 关键操作自动附加客户端签名
    this._rpcPipeline.applyClientSignature(method, p);

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

    result = await this._rpcPipeline.postprocessResult(method, p, result) as RpcResult;

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

    return await this._rpcPipeline.rawCall(method, p, { background: rpcBackground }) as RpcResult;
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
    this._rpcPipeline.signClientOperation(method, params);
  }

  // ── 事件自动解密管线 ──────────────────────────────────────

  /** 处理 transport 层推送的原始 P2P 消息 */
  private async _onRawMessageReceived(data: EventPayload): Promise<void> {
    return this._delivery.onRawMessageReceived(data);
  }

  /** 实际处理推送消息的异步任务 */
  private async _processAndPublishMessage(data: EventPayload): Promise<void> {
    return this._delivery.processAndPublishMessage(data);
  }

  /** 处理群组消息推送：自动解密后 re-publish */
  private async _onRawGroupMessageCreated(data: EventPayload): Promise<void> {
    return this._delivery.onRawGroupMessageCreated(data);
  }

  /**
   * 处理群组推送消息的异步任务。
   *
   * 带 payload 的事件（消息推送）：解密后 re-publish。
   * 不带 payload 的事件（通知）：自动 pull 最新消息，逐条解密后 re-publish。
   */
  private async _processAndPublishGroupMessage(data: EventPayload): Promise<void> {
    return this._delivery.processAndPublishGroupMessage(data);
  }

  /** 后台补齐群消息空洞 */
  private async _fillGroupGap(groupId: string): Promise<void> {
    return this._delivery.fillGroupGap(groupId);
  }

  /** 后台补齐 P2P 消息空洞 */
  private async _fillP2pGap(): Promise<void> {
    return this._delivery.fillP2pGap();
  }

  /** 只按硬上限裁剪 published guard，不能按 contiguousSeq 清理。 */
  private _prunePushedSeqs(ns: string): void {
    this._delivery.prunePushedSeqs(ns);
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
    this._delivery.markPublishedSeq(ns, seq);
  }

  private _attachCurrentInstanceContext(payload: EventPayload): EventPayload {
    return this._delivery.attachCurrentInstanceContext(payload);
  }

  private _publishAppEvent(event: string, payload: EventPayload, source = 'direct'): void | Promise<void> {
    return this._delivery.publishAppEvent(event, payload, source);
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

  private _messageEnvelopeFieldsForDebug(message: unknown): Record<string, unknown> {
    return this._delivery.messageEnvelopeFieldsForDebug(message);
  }

  private _logMessageDebug(
    stage: string,
    source: string,
    event: string,
    message: unknown,
    opts: { payloadOverride?: unknown; extra?: Record<string, unknown> } = {},
  ): void {
    this._delivery.logMessageDebug(stage, source, event, message, opts);
  }

  private _messageTargetsCurrentInstance(message: EventPayload): boolean {
    return this._delivery.messageTargetsCurrentInstance(message);
  }

  private _tryAcquirePullGate(key: string): number | null {
    return this._rpcPipeline.tryAcquirePullGate(key);
  }

  private _releasePullGate(key: string, token: number | null): void {
    this._rpcPipeline.releasePullGate(key, token);
  }

  private _pullGateKeyForCall(method: string, params: RpcParams): string {
    return this._rpcPipeline.pullGateKeyForCall(method, params);
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

  private _pullRetentionFloor(result: JsonObject, topLevelKey: string, cursorKey: string): number {
    const values: number[] = [Number(result[topLevelKey] ?? 0)];
    const cursor = isJsonObject(result.cursor as JsonValue | object | null | undefined) ? result.cursor as JsonObject : null;
    if (cursor) {
      values.push(Number(cursor[cursorKey] ?? 0));
      values.push(Number(cursor.retention_floor_seq ?? 0));
    }
    return Math.max(0, ...values.filter((value) => Number.isFinite(value)));
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

  private async _withBackgroundRpc<T>(operation: () => Promise<T> | T): Promise<T> {
    this._backgroundRpcDepth += 1;
    try {
      return await operation();
    } finally {
      this._backgroundRpcDepth = Math.max(0, this._backgroundRpcDepth - 1);
    }
  }

  private async _runPullSerialized<T>(key: string, operation: () => Promise<T> | T): Promise<T> {
    return await this._rpcPipeline.runPullSerialized(key, operation);
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
    return this._delivery.drainOrderedMessages(ns, beforeSeq, pullResponse);
  }

  private async _publishOrderedMessage(event: string, ns: string, seq: unknown, payload: EventPayload): Promise<boolean> {
    return this._delivery.publishOrderedMessage(event, ns, seq, payload);
  }

  private async _publishPulledMessage(event: string, ns: string, seq: unknown, payload: EventPayload): Promise<boolean> {
    return this._delivery.publishPulledMessage(event, ns, seq, payload);
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
    return this._delivery.fillGroupEventGap(groupId);
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

      this._groupState.handleGroupChangedV2Membership(d);

      this._delivery.handleGroupChangedEventSeq(d, groupId);

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
    return this._groupState.onGroupStateCommitted(data);
  }

  /** 群组解散后清理本地 V2 缓存、seq_tracker 和补洞去重缓存。 */
  private _cleanupDissolvedGroup(groupId: string): void {
    this._v2E2EE.deleteBootstrapCacheEntry(`group:${groupId}`);
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
        if (!certMatchesFingerprint(certPem, expectedFP)) {
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

    // H7: 严格校验指纹（DER/SPKI，64 位或 16 位短格式任一匹配即可）
    if (certFingerprint) {
      const expectedFP = certFingerprint.toLowerCase();
      if (!normalizeFingerprintHex(expectedFP)) {
        throw new ValidationError(
          `unsupported cert_fingerprint format for ${aid}: ${expectedFP.slice(0, 24)}`,
        );
      }
      if (!certMatchesFingerprint(certPem, expectedFP)) {
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
    if (!certFingerprint) {
      const bareKey = AUNClient._certCacheKey(aid);
      this._certCache.set(bareKey, entry);
      const actualFp = `sha256:${x509Cert.fingerprint256.replace(/:/g, '').toLowerCase()}`;
      this._certCache.set(AUNClient._certCacheKey(aid, actualFp), entry);
    }

    try {
      // peer 证书只存版本目录，不覆盖 cert.pem
      this._tokenStore.saveCert(aid, certPem, certFingerprint, { makeActive: false });
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
      const certPem = await _httpGetText(
        AUNClient._buildCertUrl(peerGatewayUrl, aid, certFingerprint),
        this._configModel.verifySsl,
        timeoutMs,
      );

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
    return await this._v2E2EE.decryptGroupThoughts(result);
  }

  private async _decryptMessageThoughts(result: JsonObject): Promise<JsonObject> {
    return await this._v2E2EE.decryptMessageThoughts(result);
  }

  /** 从 keystore 恢复 SeqTracker 状态 */
  private _restoreSeqTrackerState(): void {
    return this._delivery.restoreSeqTrackerState();
  }

  private _currentSeqTrackerContext(): string | null {
    if (!this._aid) return null;
    return JSON.stringify([this._aid, this._deviceId, this._slotId]);
  }

  private _resetSeqTrackingState(): void {
    this._resetV2IdentityRuntime();
    this._seqTracker = new SeqTracker();
    this._seqTrackerContext = null;
    this._gapFillDone.clear();
    this._pushedSeqs.clear();
    this._pendingOrderedMsgs.clear();
    this._pendingP2pPullUpper.clear();
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
    this._seqTracker = new SeqTracker();
    this._gapFillDone.clear();
    this._pushedSeqs.clear();
    this._pendingOrderedMsgs.clear();
    this._pendingP2pPullUpper.clear();
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
  private _saveSeqTrackerState(): void {
    return this._delivery.saveSeqTrackerState();
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

      const connectionKind = String(params.connection_kind ?? 'long');
      const isShortConnection = connectionKind === 'short';
      const hasExplicitBackgroundSync = Object.prototype.hasOwnProperty.call(params, 'background_sync');
      const backgroundSyncEnabled = this._sessionOptions.background_sync !== false
        && (!isShortConnection || hasExplicitBackgroundSync);
      if (!isShortConnection) {
        await this._v2E2EE.onConnected({ backgroundSync: backgroundSyncEnabled });
      } else {
        this._clientLog.debug('V2 session init deferred for short connection');
      }

      // connect/reconnect 成功后自动触发一次 P2P message.v2.pull，补齐离线期间积压
      // 群消息按惰性触发，不在此处主动 pull
      if (backgroundSyncEnabled) {
        void this._fillP2pGap().catch((exc) => {
          this._clientLog.warn(`schedule post-connect P2P gap fill failed: ${formatCaughtError(exc)}`);
        });
      }
      this._clientLog.debug(`_connectOnce exit: elapsed=${Date.now() - tStart}ms gateway=${gatewayUrl}, aid=${this._aid ?? ''}`);
    } catch (err) {
      this._state = (prevState === 'connected' || prevState === 'ready') ? 'standby' : (this._currentAid ? 'standby' : 'no_identity');
      this._clientLog.debug(`_connectOnce exit (error): elapsed=${Date.now() - tStart}ms gateway=${gatewayUrl} err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 兼容旧调用点；缺失时按 SDK 默认能力（V2）处理。 */
  private _captureCapabilitiesFromConnect(params: ConnectParams): void {
    void params;
  }

  /** 后台 Promise 统一兜底，避免事件回调里的异步异常变成未处理拒绝。 */
  private _safeAsync(promise: Promise<unknown>): void {
    promise.catch((exc) => {
      this._clientLog.warn(`background task exception: ${formatCaughtError(exc)}`);
    });
  }

  /** V2-only：所有加密入口都必须有 V2 session。 */
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
      this.call(method, params as RpcParams) as Promise<Record<string, unknown> | unknown>;
  }

  /**
   * 初始化 V2 session：IK 使用 AID 长期私钥，SPK 存储在 per-AID SQLite 的 v2_device_keys 表。
   * connect 成功后会自动调用；重复调用幂等。
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

  private async _getV2SenderPubDer(
    fromAid: string,
    senderDeviceId: string,
    certFingerprint?: string,
  ): Promise<Uint8Array | null> {
    return await this._v2E2EE.getV2SenderPubDer(fromAid, senderDeviceId, certFingerprint);
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
    return this._v2E2EE.scheduleSenderIKPending(args);
  }

  private async _resolveV2SenderIKPending(fromAid: string, senderDeviceId: string, groupId: string, fetchKey: string): Promise<void> {
    return await this._v2E2EE.resolveSenderIKPending(fromAid, senderDeviceId, groupId, fetchKey);
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
    return await this._v2E2EE.buildV2P2PEnvelope(opts);
  }

  /** V2 P2P 加密发送，推测性缓存失败后刷新 bootstrap 重试一次。 */
  private async _sendV2(
    to: string,
    payload: Record<string, unknown>,
    opts?: { messageId?: string; timestamp?: number; protectedHeaders?: ProtectedHeadersInput; context?: Record<string, unknown> },
  ): Promise<unknown> {
    return await this._v2E2EE.sendV2(to, payload, opts);
  }

  /** V2 P2P 拉取并解密；直接方法返回消息数组，call("message.pull") 会包装为 {messages}. */
  private async _pullV2(
    afterSeq: number = 0,
    limit: number = 50,
    opts?: { skipAutoAck?: boolean; gateLocked?: boolean; scheduleFollowup?: boolean; force?: boolean },
  ): Promise<Array<Record<string, unknown>>> {
    return await this._v2E2EE.pullV2(afterSeq, limit, opts);
  }

  /** V2 P2P ack，并触发旧 SPK 销毁自检。 */
  private async _ackV2(upToSeq?: number): Promise<unknown> {
    return await this._v2E2EE.ackV2(upToSeq);
  }

  /** V2 Group 加密发送，推测性缓存失败后刷新 bootstrap 重试一次。 */
  private async _sendGroupV2(
    groupId: string,
    payload: Record<string, unknown>,
    opts?: { messageId?: string; timestamp?: number; protectedHeaders?: ProtectedHeadersInput; context?: Record<string, unknown> },
  ): Promise<unknown> {
    return await this._v2E2EE.sendGroupV2(groupId, payload, opts);
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
    return await this._v2E2EE.buildV2GroupEnvelope(opts);
  }

  /** V2 Group 拉取并解密；直接方法返回消息数组，call("group.pull") 会包装为 {messages}. */
  private async _pullGroupV2(
    groupId: string,
    afterSeq: number = 0,
    limit: number = 50,
    opts?: {
      gateLocked?: boolean;
      scheduleFollowup?: boolean;
      explicitAfterSeq?: boolean;
      cursorParams?: RpcParams;
      ownsCursor?: boolean;
    },
  ): Promise<Array<Record<string, unknown>>> {
    return await this._v2E2EE.pullGroupV2(groupId, afterSeq, limit, opts);
  }

  private async _rawGroupAckMessages(params: RpcParams): Promise<RpcResult> {
    const p: RpcParams = { ...params };
    return await this._callRawV2Rpc('group.ack_messages', p);
  }

  /** V2 Group ack。 */
  private async _ackGroupV2(groupId: string, upToSeq?: number): Promise<unknown> {
    return await this._v2E2EE.ackGroupV2(groupId, upToSeq);
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
    this._agentMdManager.observeEnvelope(envelope);

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
    const senderCertFingerprint = String(envelope.sender_cert_fingerprint ?? '').trim().toLowerCase();
    const senderPubDer = await this._getV2SenderPubDer(fromAid, senderDeviceId, senderCertFingerprint);
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
      this._v2E2EE.scheduleGroupSpkRotation(groupIdForKeys, { reason: 'group_spk_consumed' });
    } else if (groupIdForKeys && recipientKeySource === 'peer_device_prekey') {
      this._v2E2EE.scheduleGroupSpkRegistrationAfterPeerFallback(groupIdForKeys);
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
    attachGatewayProximity(result, msg);
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
      this._agentMdManager.observeEnvelope(envelope);
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

  private _isEncryptedPushMessage(msg: JsonObject): boolean {
    return this._v2E2EE.isEncryptedPushMessage(msg);
  }

  private async _publishEncryptedPushMessage(
    normalEvent: string,
    undecryptableEvent: string,
    ns: string,
    seq: unknown,
    msg: JsonObject,
    group: boolean,
  ): Promise<boolean> {
    return await this._v2E2EE.publishEncryptedPushMessage(normalEvent, undecryptableEvent, ns, seq, msg, group);
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
    return await this._v2E2EE.putMessageThoughtEncryptedV2(params);
  }

  private async _putGroupThoughtEncryptedV2(params: RpcParams): Promise<RpcResult> {
    return await this._v2E2EE.putGroupThoughtEncryptedV2(params);
  }

  /** 解密 thought 中直接透传的 V2 envelope。 */
  private async _decryptV2EnvelopeForThought(opts: {
    envelope: Record<string, unknown>;
    fromAid: string;
  }): Promise<Record<string, unknown> | null> {
    return await this._v2E2EE.decryptV2EnvelopeForThought(opts);
  }

  private async _publishV2GroupSecurityLevel(groupId: string, bootstrap: Record<string, unknown>): Promise<void> {
    return this._groupState.publishV2GroupSecurityLevel(groupId, bootstrap);
  }

  private async _v2VerifyStateSignature(groupId: string, bootstrap: Record<string, unknown>): Promise<void> {
    return this._groupState.verifyStateSignature(groupId, bootstrap);
  }

  private async _v2CheckFork(groupId: string, serverChain: string): Promise<void> {
    return this._groupState.checkFork(groupId, serverChain);
  }

  private _v2MaybeTriggerAutoPropose(groupId: string): void {
    this._groupState.maybeTriggerAutoPropose(groupId);
  }

  private async _v2AutoProposeState(groupId: string, options?: { leaderDelay?: boolean }): Promise<void> {
    return this._groupState.autoProposeState(groupId, options);
  }

  private _v2LeaderDelayMs(input: string): number {
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

  private async _v2AutoConfirmPendingProposals(): Promise<void> {
    return this._groupState.autoConfirmPendingProposals();
  }

  private async _onV2PushNotification(data: EventPayload): Promise<void> {
    return this._delivery.onV2PushNotification(data);
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

  private async _onRawGroupV2MessageCreated(data: EventPayload): Promise<void> {
    return this._delivery.onRawGroupV2MessageCreated(data);
  }

  /** Push 通知带 payload 时的就地解密（复用 _decryptV2Message） */
  private async _decryptV2PushMessage(data: EventPayload): Promise<Record<string, unknown> | null> {
    return await this._v2E2EE.decryptV2PushMessage(data);
  }

  private async _onV2EpochRotated(data: EventPayload): Promise<void> {
    return this._v2E2EE.handleV2EpochRotated(data);
  }

  /** 按当前 AID 发现 Gateway；用于 authenticate()/connect() 的新入口。 */
  private async _resolveGatewayForAid(aid: string): Promise<string> {
    const resolvedAid = String(aid ?? this._aid ?? '').trim();
    if (!resolvedAid) {
      throw new StateError('gateway discovery requires a loaded AID');
    }
    if (this._gatewayUrl) return this._gatewayUrl;

    try {
      const loadMetadata = this._tokenStore.loadMetadata;
      const cachedGateway = typeof loadMetadata === 'function'
        ? String(loadMetadata.call(this._tokenStore, resolvedAid)?.gateway_url ?? '').trim()
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
          const saveMetadata = this._tokenStore.saveMetadata;
          if (typeof saveMetadata === 'function') {
            saveMetadata.call(this._tokenStore, resolvedAid, { gateway_url: gateway, gateway_cached_at: Date.now() });
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
    const identity = this._identity;
    if (identity === null) {
      return;
    }
    identity.access_token = accessToken;
    this._identity = identity;
    this._aid = String(identity.aid ?? this._aid ?? '');
    if (this._aid) this._logger.bindAid(this._aid);
    const persistIdentity = (this._auth as any)._persistIdentity as ((value: IdentityRecord) => void) | undefined;
    if (typeof persistIdentity === 'function') {
      persistIdentity.call(this._auth, identity);
    }
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
    request.slot_id = normalizeSlotId(request.slot_id ?? this._slotId);
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
    if ('background_sync' in params) options.background_sync = Boolean(params.background_sync);
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

        let identity = this._identity;
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

  private _validateMessageRecipient(toAid: JsonValue | object | undefined): void {
    this._rpcPipeline.validateMessageRecipient(toAid);
  }

  private _validateOutboundCall(method: string, params: RpcParams): void {
    this._rpcPipeline.validateOutboundCall(method, params);
  }

  private _injectMessageCursorContext(method: string, params: RpcParams): void {
    this._rpcPipeline.injectMessageCursorContext(method, params);
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
        this._v2E2EE.pruneExpiredBootstrapCache(AUNClient.V2_BOOTSTRAP_TTL_MS, now);
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

