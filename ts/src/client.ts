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
import { URL } from 'node:url';

import { configFromMap, getDeviceId, normalizeInstanceId, type AUNConfig } from './config.js';
import { CryptoProvider } from './crypto.js';
import { GatewayDiscovery } from './discovery.js';
import type { ProtectedHeadersInput } from './protected-headers.js';
import {
  AUNError,
  AuthError,
  ConnectionError,
  E2EEError,
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

import { AuthNamespace } from './namespaces/auth.js';
import { CustodyNamespace } from './namespaces/custody.js';
import { MetaNamespace } from './namespaces/meta.js';
import { RPCTransport } from './transport.js';
import { AuthFlow } from './auth.js';
import { SeqTracker } from './seq-tracker.js';
import { V2Session, V2KeyStore, type CallFn } from './v2/session/index.js';
import {
  encryptP2PMessage, encryptGroupMessage, decryptMessage,
  type Target, type StateCommitmentAAD,
} from './v2/e2ee/index.js';
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
} from './types.js';


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
  'group.send', 'group.kick', 'group.add_member',
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
function _httpGetText(url: string, verifySsl: boolean): Promise<string> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;
    const options: https.RequestOptions = { timeout: 30_000 };
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
  private _state: string = 'idle';

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

  /** Auth 命名空间 */
  readonly auth: AuthNamespace;
  /** AID 托管命名空间 */
  readonly custody: CustodyNamespace;
  /** Meta 命名空间（心跳、状态、信任根管理） */
  readonly meta: MetaNamespace;

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

  // 本地 agent.md 文件路径与对应 etag（quoted sha256 hex，与服务端 _agent_md_etag 一致）。
  // 由 setLocalAgentMdPath() 设置；用于跟服务端 RPC 注入的 _meta.agent_md_etag 比对，
  // 触发"本地未发布到服务端"或"服务端版本更新"的 UI 提示。
  private _localAgentMdPath: string = '';
  private _localAgentMdEtag: string = '';
  // gateway 在 RPC envelope._meta.agent_md_etag 注入的服务端 etag；纯观察，无下游依赖。
  private _remoteAgentMdEtag: string = '';

  /** 消息序列号跟踪器（群消息 + P2P 空洞检测） */
  private _seqTracker: SeqTracker = new SeqTracker();
  private _seqTrackerContext: string | null = null;

  /** 惰性群同步：已同步过的 group_id 集合 */
  private _groupSynced: Set<string> = new Set();

  /** 补洞去重：已完成/进行中的 key -> 开始时间戳，防止重复 pull 同一区间 */
  private _gapFillDone: Map<string, number> = new Map();
  /** 已发布到应用层的 seq 集合（按命名空间），补洞路径 publish 前检查以避免重复分发 */
  private _pushedSeqs: Map<string, Set<number>> = new Map();
  /** 已解密但因 seq 空洞暂缓发布的应用层消息（按 namespace -> seq） */
  private _pendingOrderedMsgs: Map<string, Map<number, { event: string; payload: EventPayload }>> = new Map();

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
  private _v2PullInflight = false;
  private _v2PullPending = false;
  private static readonly V2_BOOTSTRAP_TTL_MS = 60 * 60 * 1000;
  private static readonly V2_RETRYABLE_CODES = new Set([-33011, -33012, -33050, -33052, -33054]);
  private static readonly V2_SIG_CACHE_TTL_MS = 600_000;
  private static readonly V2_SIG_CACHE_MAX = 16_384;

  private _reconnectActive = false;
  private _reconnectAbort: AbortController | null = null;
  private _serverKicked = false;
  /** 缓存最近一次 gateway.disconnect 信息（含服务端附带的 detail），用于后续 connection.state 透传 */
  private _lastDisconnectInfo: { code?: any; reason?: string; detail?: Record<string, any> } | null = null;
  private _logger!: AUNLogger;
  private _clientLog!: ModuleLogger;

  constructor(config?: RpcParams, debug = false) {
    const rawConfig: RpcParams = { ...(config ?? {}) };
    this._configModel = configFromMap(rawConfig);
    const initAid = String(rawConfig.aid ?? '').trim() || null;
    this.config = {
      aun_path: this._configModel.aunPath,
      root_ca_path: this._configModel.rootCaPath,
      seed_password: this._configModel.seedPassword,
    };

    // 初始化 Logger（per-client 单例，必须最早创建）
    const debugFlag = this._configModel.debug || debug;
    this._logger = new AUNLogger({
      debug: debugFlag,
      aunPath: this._configModel.aunPath,
    });
    this._clientLog = this._logger.for('aun_core.client');
    if (debugFlag) {
      this._clientLog.info(`AUNClient initialized (debug=true, aunPath=${this._configModel.aunPath})`);
    }

    this._dispatcher = new EventDispatcher(this._logger.for('aun_core.events'));
    this._discovery = new GatewayDiscovery({ verifySsl: this._configModel.verifySsl });

    const keystore = new FileKeyStore(
      this._configModel.aunPath,
      {
        encryptionSeed: this._configModel.seedPassword ?? undefined,
        logger: this._logger.for('aun_core.keystore'),
        secretStoreLogger: this._logger.for('aun_core.secret-store'),
      },
    );
    this._keystore = keystore;
    this._deviceId = getDeviceId(this._configModel.aunPath);

    this._slotId = '';
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
    });
    this._aid = initAid;

    this._transport = new RPCTransport({
      eventDispatcher: this._dispatcher,
      timeout: 10_000,
      onDisconnect: (err, closeCode) => this._handleTransportDisconnect(err, closeCode),
      verifySsl: this._configModel.verifySsl,
      logger: this._logger.for('aun_core.transport'),
    });
    this._transport.setMetaObserver((meta) => this._observeRpcMeta(meta));

    this.auth = new AuthNamespace(this);
    this.custody = new CustodyNamespace(this);
    this.meta = new MetaNamespace(this);
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

  /**
   * 读取本地 agent.md，签名后上传，并刷新本地 etag。
   */
  async publishAgentMd(path: string): Promise<Record<string, unknown>> {
    const rawPath = String(path ?? '').trim();
    if (!rawPath) {
      throw new ValidationError('publishAgentMd requires non-empty path');
    }
    const content = fs.readFileSync(rawPath).toString('utf-8');
    const signed = await this.auth.signAgentMd(content);
    const result = await this.auth.uploadAgentMd(signed);
    const digest = crypto.createHash('sha256').update(signed, 'utf-8').digest('hex');
    this._localAgentMdEtag = `"${digest}"`;
    this._localAgentMdPath = rawPath;
    return result as Record<string, unknown>;
  }

  /**
   * 下载 agent.md 并自动验签；可选写盘；目标是自身 AID 时刷新本地 etag。
   */
  async fetchAgentMd(aid?: string | null, savePath?: string | null): Promise<{
    aid: string;
    content: string;
    signature: Record<string, unknown>;
    in_sync: boolean | null;
    saved_to: string | null;
    save_error: string | null;
  }> {
    const target = String(aid ?? this._aid ?? '').trim();
    if (!target) {
      throw new ValidationError('fetchAgentMd requires aid (or local AID)');
    }

    const content = await this.auth.downloadAgentMd(target);
    const signature = await this.auth.verifyAgentMd(content, { aid: target });

    const isSelf = target === (this._aid ?? '');
    let inSync: boolean | null = null;
    if (isSelf) {
      const digest = crypto.createHash('sha256').update(content, 'utf-8').digest('hex');
      this._localAgentMdEtag = `"${digest}"`;
      const local = this._localAgentMdEtag || '';
      const remote = this._remoteAgentMdEtag || '';
      inSync = local && remote ? local === remote : false;
    }

    let savedTo: string | null = null;
    let saveError: string | null = null;
    const rawSavePath = String(savePath ?? '').trim();
    if (rawSavePath) {
      try {
        fs.writeFileSync(rawSavePath, content, 'utf-8');
        savedTo = rawSavePath;
      } catch (exc) {
        saveError = exc instanceof Error ? exc.message : String(exc);
      }
    }

    return {
      aid: target,
      content,
      signature: signature as Record<string, unknown>,
      in_sync: inSync,
      saved_to: savedTo,
      save_error: saveError,
    };
  }

  /**
   * 记录本地 agent.md 文件路径并一次性计算 etag（quoted sha256，与服务端一致）。
   *
   * - path 为空字符串：清除本地 path 与 etag。
   * - 文件不存在 / 读取失败：清除 etag 并返回空串，不抛异常（应用可读 getLocalAgentMdEtag()
   *   为空判断）。
   * - 浏览器环境无文件系统：直接返回空串，记录 warn 日志。
   * - 文件变更后需要重新调用 setLocalAgentMdPath() 触发重算（按设计：设置时一次性计算）。
   *
   * 返回当前 etag（quoted hex 或空串）。
   */
  setLocalAgentMdPath(path: string): string {
    const rawPath = String(path ?? '').trim();
    if (!rawPath) {
      this._localAgentMdPath = '';
      this._localAgentMdEtag = '';
      return '';
    }
    // 浏览器环境没有 fs，直接退回空串。Node 环境才尝试读文件。
    const isNode = typeof process !== 'undefined' && !!process.versions?.node;
    if (!isNode) {
      this._clientLog.warn(`setLocalAgentMdPath skipped: not running in Node.js (path=${rawPath})`);
      this._localAgentMdPath = rawPath;
      this._localAgentMdEtag = '';
      return '';
    }
    this._localAgentMdPath = rawPath;
    try {
      const data = fs.readFileSync(rawPath);
      const digest = crypto.createHash('sha256').update(data).digest('hex');
      this._localAgentMdEtag = `"${digest}"`;
    } catch (err) {
      this._clientLog.warn(`setLocalAgentMdPath 读取失败 path=${rawPath} err=${err instanceof Error ? err.message : String(err)}`);
      this._localAgentMdEtag = '';
    }
    return this._localAgentMdEtag;
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

  /** transport 的 meta observer：吸收 gateway 注入的 _meta 字段。失败不影响业务。 */
  private _observeRpcMeta(meta: Record<string, unknown>): void {
    if (!meta || typeof meta !== 'object') return;
    const etag = String(meta.agent_md_etag ?? '').trim();
    if (etag) {
      this._remoteAgentMdEtag = etag;
    }
  }

  /** 连接状态 */
  get state(): string {
    return this._state;
  }

  /** 最近一次 gateway health check 结果，null 表示尚未检查 */
  get gatewayHealth(): boolean | null {
    return this._discovery.lastHealthy;
  }

  /** 向 gatewayUrl 的 /health 端点发送 GET 请求，检查网关可用性 */
  async checkGatewayHealth(gatewayUrl: string, timeout = 5_000): Promise<boolean> {
    const tStart = Date.now();
    this._clientLog.debug(`checkGatewayHealth enter: gatewayUrl=${gatewayUrl}`);
    try {
      const result = await this._discovery.checkHealth(gatewayUrl, timeout);
      this._clientLog.debug(`checkGatewayHealth exit: elapsed=${Date.now() - tStart}ms healthy=${result}`);
      return result;
    } catch (err) {
      this._clientLog.debug(`checkGatewayHealth exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  // ── 生命周期 ──────────────────────────────────────────────

  /**
   * 连接到 Gateway。
   *
   * @param auth - 认证参数（必须包含 access_token 和 gateway）
   * @param options - 会话选项（auto_reconnect、heartbeat_interval 等）
   */
  async connect(
    auth: RpcParams,
    options?: RpcParams,
  ): Promise<void> {
    const tStart = Date.now();
    if (this._state !== 'idle' && this._state !== 'closed' && this._state !== 'disconnected') {
      throw new StateError(`connect not allowed in state ${this._state}`);
    }
    this._state = 'connecting';
    const params = { ...auth };
    if (options) Object.assign(params, options);
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
    try {
      await this._connectOnce(normalized, false);
      this._clientLog.debug(`connect exit: elapsed=${Date.now() - tStart}ms aid=${this._aid ?? ''}, state=${this._state}`);
    } catch (err) {
      // 连接失败时回退状态，允许重试
      if (this._state === 'connecting' || this._state === 'authenticating') {
        this._state = 'disconnected';
      }
      this._clientLog.error(`connect failed: ${formatCaughtError(err)}`, err instanceof Error ? err : undefined);
      this._clientLog.debug(`connect exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
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
      if (this._state === 'idle' || this._state === 'closed') {
        const closableKeyStore = this._keystore as KeyStore & { close?: () => void };
        closableKeyStore.close?.();
        this._state = 'closed';
        this._logger.close();
        this._resetSeqTrackingState();
        this._clientLog.debug(`close exit: elapsed=${Date.now() - tStart}ms (was idle/closed)`);
        return;
      }
      await this._transport.close();
      const closableKeyStore = this._keystore as KeyStore & { close?: () => void };
      closableKeyStore.close?.();
      this._state = 'closed';
      this._logger.close();
      await this._dispatcher.publish('connection.state', { state: this._state });
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
      if (this._state !== 'connected' && this._state !== 'reconnecting') {
        this._clientLog.debug(`disconnect exit: elapsed=${Date.now() - tStart}ms (state=${this._state})`);
        return;
      }
      this._saveSeqTrackerState();
      this._stopBackgroundTasks();
      this._stopReconnect();
      await this._transport.close();
      this._state = 'disconnected';
      await this._dispatcher.publish('connection.state', { state: this._state });
      this._clientLog.debug(`disconnect exit: elapsed=${Date.now() - tStart}ms`);
    } catch (err) {
      this._clientLog.debug(`disconnect exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /**
   * 列出本地所有已存储的身份摘要（仅返回有有效私钥的 AID）。
   */
  listIdentities(): Array<{ aid: string; metadata?: Record<string, unknown> }> {
    const tStart = Date.now();
    this._clientLog.debug(`listIdentities enter`);
    try {
    const listFn = (this._keystore as KeyStore & {
      listIdentities?: () => string[];
    }).listIdentities;
    if (typeof listFn !== 'function') {
      this._clientLog.debug(`listIdentities exit: elapsed=${Date.now() - tStart}ms (no_list_fn)`);
      return [];
    }
    const aids = listFn.call(this._keystore);
    const summaries: Array<{ aid: string; metadata?: Record<string, unknown> }> = [];
    for (const aid of [...aids].sort()) {
      const identity = this._keystore.loadIdentity(aid);
      if (!identity || !identity.private_key_pem) continue;
      const summary: { aid: string; metadata?: Record<string, unknown> } = { aid };
      const loadMetadata = (this._keystore as KeyStore & {
        loadMetadata?: (aid: string) => Record<string, unknown> | null;
      }).loadMetadata;
      if (typeof loadMetadata === 'function') {
        const md = loadMetadata.call(this._keystore, aid);
        if (md) summary.metadata = md;
      }
      summaries.push(summary);
    }
    this._clientLog.debug(`listIdentities exit: elapsed=${Date.now() - tStart}ms count=${summaries.length}`);
    return summaries;
    } catch (err) {
      this._clientLog.debug(`listIdentities exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
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
    if (method.startsWith('group.') && this._deviceId && p.device_id === undefined) {
      p.device_id = this._deviceId;
    }
    if (method.startsWith('group.') && p.slot_id === undefined) {
      p.slot_id = this._slotId;
    }

    // 自动加密：message.send 默认加密（encrypt 默认 true）— V2-only
    if (method === 'message.send') {
      const encrypt = p.encrypt ?? true;
      delete p.encrypt;
      if (encrypt) {
        return await this.sendV2(String(p.to ?? ''), p.payload as Record<string, unknown>, {
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
      const encrypt = p.encrypt ?? true;
      delete p.encrypt;
      if (encrypt) {
        return await this.sendGroupV2(String(p.group_id ?? ''), p.payload as Record<string, unknown>, {
          messageId: String(p.message_id ?? '') || undefined,
          timestamp: p.timestamp as number | undefined,
          protectedHeaders: this._protectedHeadersFromParams(p) as Record<string, unknown> | undefined,
          context: isJsonObject(p.context) ? p.context : undefined,
        }) as RpcResult;
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
        return await this._putGroupThoughtEncryptedV2(p);
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
        return await this._putMessageThoughtEncryptedV2(p);
      }
    }

    if (method === 'message.pull' && this._clientUsesV2P2P()) {
      await this._ensureV2SessionReady('message.pull');
      const messages = await this.pullV2(Number(p.after_seq ?? 0) || 0, Number(p.limit ?? 50) || 50);
      return { messages } as RpcResult;
    }

    if (method === 'message.ack' && this._clientUsesV2P2P()) {
      await this._ensureV2SessionReady('message.ack');
      return await this.ackV2(Number(p.seq ?? p.up_to_seq ?? 0) || undefined) as RpcResult;
    }

    if (method === 'group.pull' && this._clientUsesV2Group() && p.group_id) {
      await this._ensureV2SessionReady('group.pull');
      const messages = await this.pullGroupV2(
        String(p.group_id),
        Number(p.after_seq ?? p.after_message_seq ?? 0) || 0,
        Number(p.limit ?? 50) || 50,
      );
      return { messages } as RpcResult;
    }

    if (method === 'group.ack_messages' && this._clientUsesV2Group() && p.group_id) {
      await this._ensureV2SessionReady('group.ack_messages');
      return await this.ackGroupV2(
        String(p.group_id),
        Number(p.seq ?? p.msg_seq ?? p.up_to_seq ?? 0) || undefined,
      ) as RpcResult;
    }

    // 关键操作自动附加客户端签名
    if (SIGNED_METHODS.has(method)) {
      this._signClientOperation(method, p);
    }

    // P1-23: 非幂等方法使用更长超时
    const callTimeout = NON_IDEMPOTENT_METHODS.has(method) ? NON_IDEMPOTENT_TIMEOUT_MS : undefined;
    let result = callTimeout
      ? await this._transport.call(method, p, callTimeout)
      : await this._transport.call(method, p);

    if (method === 'group.thought.get' && isJsonObject(result)) {
      result = await this._decryptGroupThoughts(result);
    }
    if (method === 'message.thought.get' && isJsonObject(result)) {
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

  // ── 便利方法 ──────────────────────────────────────────────

  /** 心跳检测 */
  async ping(params?: RpcParams): Promise<RpcResult> {
    const tStart = Date.now();
    this._clientLog.debug(`ping enter`);
    try {
      const result = await this.call('meta.ping', params ?? {});
      this._clientLog.debug(`ping exit: elapsed=${Date.now() - tStart}ms`);
      return result;
    } catch (err) {
      this._clientLog.debug(`ping exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 获取服务端状态 */
  async status(params?: RpcParams): Promise<RpcResult> {
    const tStart = Date.now();
    this._clientLog.debug(`status enter`);
    try {
      const result = await this.call('meta.status', params ?? {});
      this._clientLog.debug(`status exit: elapsed=${Date.now() - tStart}ms`);
      return result;
    } catch (err) {
      this._clientLog.debug(`status exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 获取信任根证书列表 */
  async trustRoots(params?: RpcParams): Promise<RpcResult> {
    const tStart = Date.now();
    this._clientLog.debug(`trustRoots enter`);
    try {
      const result = await this.call('meta.trust_roots', params ?? {});
      this._clientLog.debug(`trustRoots exit: elapsed=${Date.now() - tStart}ms`);
      return result;
    } catch (err) {
      this._clientLog.debug(`trustRoots exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
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
        this._publishAppEvent('message.undecryptable', safeEvent).catch(() => {});
      }
    });
    this._clientLog.debug(`_onRawMessageReceived exit: elapsed=${Date.now() - tStart}ms (handler dispatched)`);
  }

  /** 实际处理推送消息的异步任务 */
  private async _processAndPublishMessage(data: EventPayload): Promise<void> {
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
    if (seq !== undefined && seq !== null && this._aid) {
      const ns = `p2p:${this._aid}`;
      const needPull = this._seqTracker.onMessageSeq(ns, seq);
      if (needPull) {
        this._clientLog.debug(`P2P seq gap detected: ns=${ns}, seq=${seq}, contiguous=${this._seqTracker.getContiguousSeq(ns)}`);
        this._fillP2pGap().catch(exc => this._clientLog.warn(`background gap fill trigger failed: ${formatCaughtError(exc)}`));
      }
      // auto-ack contiguous_seq
      const contig = this._seqTracker.getContiguousSeq(ns);
      if (contig > 0) {
        this._transport.call('message.ack', {
          seq: contig,
          device_id: this._deviceId,
          slot_id: this._slotId,
        }).catch((e) => { this._clientLog.debug(`P2P auto-ack failed: ${formatCaughtError(e)}`); });
      }
      // 即时持久化 cursor，异常断连后不回退
      this._saveSeqTrackerState();
    }

    // V2-only：普通 _raw.message.received 只承载明文；V2 密文由 peer.v2.message_received 通知触发 pull。
    if (seq !== undefined && seq !== null && this._aid) {
      const ns = `p2p:${this._aid}`;
      await this._publishOrderedMessage('message.received', ns, seq, msg);
    } else {
      await this._publishAppEvent('message.received', msg);
    }
  }

  /** 处理群组消息推送：自动解密后 re-publish */
  private async _onRawGroupMessageCreated(data: EventPayload): Promise<void> {
    const tStart = Date.now();
    if (isJsonObject(data)) {
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
        this._publishAppEvent('group.message_undecryptable', safeEvent).catch(() => {});
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
      await this._publishAppEvent('group.message_created', data);
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
      await this._autoPullGroupMessages(msg);
      return;
    }
    if (groupId && seq !== undefined && seq !== null) {
      const ns = `group:${groupId}`;
      const needPull = this._seqTracker.onMessageSeq(ns, seq);
      if (needPull) {
        this._clientLog.debug(`group message seq gap detected: group=${groupId}, seq=${seq}, contiguous=${this._seqTracker.getContiguousSeq(ns)}`);
        this._fillGroupGap(groupId).catch(exc => this._clientLog.warn(`background gap fill trigger failed: ${formatCaughtError(exc)}`));
      }
      const contig = this._seqTracker.getContiguousSeq(ns);
      if (contig > 0) {
        this._transport.call('group.ack_messages', {
          group_id: groupId,
          msg_seq: contig,
          device_id: this._deviceId,
          slot_id: this._slotId,
        }).catch((e) => { this._clientLog.debug(`group message auto-ack failed: group=${groupId} ${formatCaughtError(e)}`); });
      }
      this._saveSeqTrackerState();
    }

    // V2-only：普通 group.message_created 只承载明文；V2 密文由 group.v2.message_created 通知触发 pull。
    if (groupId && seq !== undefined && seq !== null) {
      const nsKey = `group:${groupId}`;
      await this._publishOrderedMessage('group.message_created', nsKey, seq, msg);
    } else {
      await this._publishAppEvent('group.message_created', msg);
    }
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
          // onPullResult 已在 call() 拦截器中调用，此处不再重复
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
      this._clientLog.debug(`auto pull group messages failed: ${formatCaughtError(exc)}`);
    }
    await this._publishAppEvent('group.message_created', notification);
  }

  /** 后台补齐群消息空洞 */
  private async _fillGroupGap(groupId: string): Promise<void> {
    const ns = `group:${groupId}`;
    const afterSeq = this._seqTracker.getContiguousSeq(ns);
    // 去重：同一 (group:id:after_seq) 只补一次
    const dedupKey = `group_msg:${groupId}:${afterSeq}`;
    if (this._gapFillDone.has(dedupKey)) return;
    this._gapFillDone.set(dedupKey, Date.now());
    this._clientLog.debug(`group message gap fill start: group=${groupId}, after_seq=${afterSeq}`);
    try {
      const result = await this.call('group.pull', {
        group_id: groupId,
        after_message_seq: afterSeq,
        device_id: this._deviceId,
        limit: 50,
      });
      let filled = 0;
      if (isJsonObject(result)) {
        const messages = result.messages;
        if (Array.isArray(messages)) {
          // onPullResult 已在 call() 拦截器中调用，此处不再重复
          const pushed = this._pushedSeqs.get(ns);
          for (const msg of messages) {
            if (isJsonObject(msg)) {
              const s = (msg as Record<string, unknown>).seq as number | undefined;
              if (pushed && s !== undefined && s !== null && pushed.has(s)) continue;
              if (s !== undefined && s !== null) {
                await this._publishPulledMessage('group.message_created', ns, s, msg);
              } else {
                await this._publishAppEvent('group.message_created', msg);
              }
              filled += 1;
            }
          }
          this._prunePushedSeqs(ns);
        }
      }
      this._clientLog.debug(`group message gap fill done: group=${groupId}, after_seq=${afterSeq}, filled=${filled}`);
    } catch (exc) {
      this._clientLog.warn(`group message gap fill failed: ${formatCaughtError(exc)}`);
    } finally {
      this._gapFillDone.delete(dedupKey);
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
    this._gapFillDone.set(dedupKey, Date.now());
    this._clientLog.debug(`P2P message gap fill start: after_seq=${afterSeq}`);
    try {
      const result = await this.call('message.pull', {
        after_seq: afterSeq,
        limit: 50,
      });
      let filled = 0;
      if (isJsonObject(result)) {
        const messages = result.messages;
        if (Array.isArray(messages)) {
          // onPullResult 已在 call() 拦截器中调用，此处不再重复
          const pushed = this._pushedSeqs.get(ns);
          for (const msg of messages) {
            if (isJsonObject(msg)) {
              const s = (msg as Record<string, unknown>).seq as number | undefined;
              if (pushed && s !== undefined && s !== null && pushed.has(s)) continue;
              if (s !== undefined && s !== null) {
                await this._publishPulledMessage('message.received', ns, s, msg);
              } else {
                await this._publishAppEvent('message.received', msg);
              }
              filled += 1;
            }
          }
          this._prunePushedSeqs(ns);
        }
      }
      this._clientLog.debug(`P2P message gap fill done: after_seq=${afterSeq}, filled=${filled}`);
    } catch (exc) {
      this._clientLog.warn(`P2P message gap fill failed: ${formatCaughtError(exc)}`);
    } finally {
      this._gapFillDone.delete(dedupKey);
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
    if (this._deviceId && !String(result.device_id ?? '').trim()) {
      result.device_id = this._deviceId;
    }
    if (this._slotId && !String(result.slot_id ?? '').trim()) {
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
    const targetDeviceId = String(message.device_id ?? '').trim();
    if (targetDeviceId && this._deviceId && targetDeviceId !== this._deviceId) {
      return false;
    }
    const targetSlotId = String(message.slot_id ?? '').trim();
    if (targetSlotId && this._slotId && targetSlotId !== this._slotId) {
      return false;
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

  /** 后台补齐群事件空洞 */
  private async _fillGroupEventGap(groupId: string): Promise<void> {
    const ns = `group_event:${groupId}`;
    const afterSeq = this._seqTracker.getContiguousSeq(ns);
    // 去重：同一 (group_evt:id:after_seq) 只补一次
    const dedupKey = `group_evt:${groupId}:${afterSeq}`;
    if (this._gapFillDone.has(dedupKey)) return;
    this._gapFillDone.set(dedupKey, Date.now());
    this._clientLog.debug(`group event gap fill start: group=${groupId}, after_seq=${afterSeq}`);
    try {
      const result = await this.call('group.pull_events', {
        group_id: groupId,
        after_event_seq: afterSeq,
        device_id: this._deviceId,
        limit: 50,
      });
      let filled = 0;
      if (isJsonObject(result)) {
        const events = result.events;
        if (Array.isArray(events)) {
          this._seqTracker.onPullResult(ns, events.filter(isJsonObject));
          const cursor = isJsonObject(result.cursor) ? result.cursor : null;
          const serverAck = cursor ? Number(cursor.current_seq ?? 0) : 0;
          if (serverAck > 0) {
            const contigBefore = this._seqTracker.getContiguousSeq(ns);
            if (contigBefore < serverAck) {
              this._clientLog.info(`group.pull_events retention-floor advance: ns=${ns} contiguous=${contigBefore} -> cursor.current_seq=${serverAck}`);
              this._seqTracker.forceContiguousSeq(ns, serverAck);
            }
          }
          // 持久化 cursor + ack_events（与 Python 对齐）
          this._saveSeqTrackerState();
          const contig = this._seqTracker.getContiguousSeq(ns);
          if (contig > 0 && (events.length > 0 || serverAck > 0)) {
            this._transport.call('group.ack_events', {
              group_id: groupId,
              event_seq: contig,
              device_id: this._deviceId,
              slot_id: this._slotId,
            }).catch((e) => { this._clientLog.debug(`group event auto-ack failed: group=${groupId} ${formatCaughtError(e)}`); });
          }
          for (const evt of events) {
            if (isJsonObject(evt)) {
              evt._from_gap_fill = true;
              const et = String(evt.event_type ?? '');
              // 消息事件由 _fillGroupGap 负责，事件补洞不重复投递
              if (et === 'group.message_created') continue;
              // 验签：有 client_signature 就验（与实时事件路径对齐）
              const cs = evt.client_signature;
              if (cs && typeof cs === 'object') {
                evt._verified = await this._verifyEventSignatureAsync(evt, cs as JsonObject);
              }
              // group.changed 或缺失/其他 → 发布到 group.changed（向后兼容）
              await this._dispatcher.publish('group.changed', evt);
              filled += 1;
            }
          }
        }
      }
      this._clientLog.debug(`group event gap fill done: group=${groupId}, after_seq=${afterSeq}, filled=${filled}`);
    } catch (exc) {
      this._clientLog.warn(`group event gap fill failed: ${formatCaughtError(exc)}`);
    } finally {
      this._gapFillDone.delete(dedupKey);
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
        d._verified = await this._verifyEventSignatureAsync(d, cs);
      }
      await this._dispatcher.publish('group.changed', d);

      // V2-only：成员/设备变化会影响 group.v2.bootstrap 的设备集与 state commitment。
      if (groupId) {
        this._v2BootstrapCache.delete(`group:${groupId}`);
      }
      if (groupId && action === 'upsert' && this._v2Session) {
        this._safeAsync(this._v2AutoProposeState(groupId, { leaderDelay: true }));
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
          }).catch((e) => { this._clientLog.debug(`group event push auto-ack failed: group=${groupId} ${formatCaughtError(e)}`); });
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
      const verified = await this._verifyEventSignatureAsync(d, cs);
      if (verified === false) {
        this._clientLog.warn(`state_committed committer signature verification failed group=${groupId}`);
        return;
      }
      d._verified = verified;
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

  /**
   * 获取对方证书（带缓存 + 完整 PKI 验证）。  /**
   * 获取对方证书（带缓存 + 完整 PKI 验证）。
   * 跨域时自动路由到 peer 所在域的 Gateway。
   */
  private async _fetchPeerCert(aid: string, certFingerprint?: string): Promise<string> {
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

    // 跨域时用 peer 所在域的 Gateway URL
    const peerGatewayUrl = AUNClient._resolvePeerGatewayUrl(gatewayUrl, aid);
    let certPem: string;
    try {
      const certUrl = AUNClient._buildCertUrl(peerGatewayUrl, aid, certFingerprint);
      certPem = await _httpGetText(certUrl, this._configModel.verifySsl);
    } catch (exc) {
      if (!certFingerprint) {
        throw exc;
      }
      const fallbackCert = await _httpGetText(
        AUNClient._buildCertUrl(peerGatewayUrl, aid),
        this._configModel.verifySsl,
      );
      certPem = fallbackCert;
    }

    // H7: 严格校验指纹（DER SHA-256 或 SPKI SHA-256 任一匹配即可）
    if (certFingerprint) {
      const expectedFP = String(certFingerprint).trim().toLowerCase();
      if (!expectedFP.startsWith('sha256:')) {
        throw new ValidationError(
          `unsupported cert_fingerprint format for ${aid}: ${expectedFP.slice(0, 24)}`,
        );
      }
      const expectedHex = expectedFP.slice('sha256:'.length);
      const x509Cert = new crypto.X509Certificate(certPem);
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

    // 完整 PKI 验证
    try {
      await this._auth.verifyPeerCertificate(peerGatewayUrl, certPem, aid);
    } catch (exc) {
      throw new ValidationError(
        `peer cert verification failed for ${aid}: ${exc instanceof Error ? exc.message : String(exc)}`,
      );
    }

    const nowSec = Date.now() / 1000;
    this._certCache.set(cacheKey, {
      certPem,
      validatedAt: nowSec,
      refreshAfter: nowSec + PEER_CERT_CACHE_TTL,
    });

    try {
      // peer 证书只存版本目录，不覆盖 cert.pem
      this._keystore.saveCert(aid, certPem, certFingerprint, { makeActive: false });
    } catch (exc) {
      this._clientLog.error(`failed to write cert to keystore (aid=${aid}, fp=${certFingerprint ?? ''}): ${formatCaughtError(exc)}`, exc instanceof Error ? exc : undefined);
    }

    this._clientLog.debug(`_fetchPeerCert exit: elapsed=${Date.now() - tStart}ms aid=${aid} (fetched)`);
    return certPem;
    } catch (err) {
      this._clientLog.debug(`_fetchPeerCert exit (error): elapsed=${Date.now() - tStart}ms aid=${aid} err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  private async _decryptGroupThoughts(result: JsonObject): Promise<JsonObject> {
    if (!result.found) {
      return { ...result, thoughts: [] as JsonValue[] };
    }
    const items = Array.isArray(result.thoughts) ? result.thoughts.filter(isJsonObject) : [];
    if (items.length === 0) {
      return { ...result, thoughts: [] as JsonValue[] };
    }
    const groupId = String(result.group_id ?? '');
    const senderAid = String(result.sender_aid ?? '');
    const thoughts: JsonObject[] = [];
    for (const item of items) {
      const payload = isJsonObject(item.payload) ? item.payload : null;
      const thoughtId = String(item.thought_id ?? item.message_id ?? '');
      const fromAid = String(item.from ?? item.sender_aid ?? senderAid);
      let decryptFailed = false;
      let decryptedPayload: JsonValue | object = payload ?? {};
      let e2ee: JsonValue | undefined;
      if (payload?.type === 'e2ee.group_encrypted' && String(payload.version ?? '') === 'v2') {
        const plain = await this._decryptV2EnvelopeForThought({ envelope: payload, fromAid });
        if (plain === null) {
          decryptFailed = true;
        } else {
          decryptedPayload = plain;
          e2ee = {
            version: 'v2',
            suite: String(payload.suite ?? ''),
            encryption_mode: `v2_${String(payload.suite ?? 'unknown')}`,
            forward_secrecy: true,
          } as JsonObject;
        }
      } else if (payload?.type === 'e2ee.group_encrypted') {
        decryptFailed = true;
      }
      const thought: JsonObject = {
        thought_id: thoughtId,
        message_id: thoughtId,
        payload: decryptFailed ? (payload ?? {}) : decryptedPayload as JsonValue,
        created_at: item.created_at,
      };
      if (e2ee !== undefined) thought.e2ee = e2ee;
      if (decryptFailed) thought.decrypt_failed = true;
      if ('context' in item) thought.context = item.context;
      thoughts.push(thought);
    }
    return { ...result, thoughts };
  }

  private async _decryptMessageThoughts(result: JsonObject): Promise<JsonObject> {
    if (!result.found) {
      return { ...result, thoughts: [] as JsonValue[] };
    }
    const items = Array.isArray(result.thoughts) ? result.thoughts.filter(isJsonObject) : [];
    if (items.length === 0) {
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
      let decryptFailed = false;
      let decryptedPayload: JsonValue | object = payload ?? {};
      let e2ee: JsonValue | undefined;
      if (payload?.type === 'e2ee.p2p_encrypted' && String(payload.version ?? '') === 'v2') {
        const plain = await this._decryptV2EnvelopeForThought({ envelope: payload, fromAid });
        if (plain === null) {
          decryptFailed = true;
        } else {
          decryptedPayload = plain;
          e2ee = {
            version: 'v2',
            suite: String(payload.suite ?? ''),
            encryption_mode: `v2_${String(payload.suite ?? 'unknown')}`,
            forward_secrecy: true,
          } as JsonObject;
        }
      } else if (payload?.type === 'e2ee.encrypted' || payload?.type === 'e2ee.p2p_encrypted') {
        decryptFailed = true;
      }
      const thought: JsonObject = {
        thought_id: thoughtId,
        message_id: thoughtId,
        from: fromAid,
        to: toAid,
        payload: decryptFailed ? (payload ?? {}) : decryptedPayload as JsonValue,
        created_at: item.created_at,
      };
      if (e2ee !== undefined) thought.e2ee = e2ee;
      if (decryptFailed) thought.decrypt_failed = true;
      if ('context' in item) thought.context = item.context;
      thoughts.push(thought);
    }
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
    this._groupSynced.clear();
  }

  private _refreshSeqTrackerContext(): void {
    const nextContext = this._currentSeqTrackerContext();
    if (nextContext === this._seqTrackerContext) return;
    this._seqTracker = new SeqTracker();
    this._gapFillDone.clear();
    this._pushedSeqs.clear();
    this._pendingOrderedMsgs.clear();
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

      this._state = 'connected';
      this._connectedAt = Date.now();
      this._clientLog.debug(`auth complete, connection ready: aid=${this._aid ?? ''}, gateway=${gatewayUrl}`);
      await this._dispatcher.publish('connection.state', { state: this._state, gateway: gatewayUrl });

      // auth 阶段 aid 可能被 identity 覆盖（上方 this._aid = identity.aid）；
      // 若 context 发生变化，重新 refresh + restore，保持 tracker 与真实身份一致。
      if (this._seqTrackerContext !== this._currentSeqTrackerContext()) {
        this._refreshSeqTrackerContext();
        this._restoreSeqTrackerState();
      }

      this._startBackgroundTasks();

      // V2 E2EE：初始化 session 并注册本设备 SPK。
      try {
        await this.initV2Session();
      } catch (exc) {
        this._clientLog.warn(`V2 session init failed (non-fatal): ${formatCaughtError(exc)}`);
      }

      // connect/reconnect 成功后自动触发一次 P2P message.pull，补齐离线期间积压
      // 群消息按惰性触发，不在此处主动 pull
      void this._fillP2pGap().catch((exc) => {
        this._clientLog.warn(`schedule post-connect P2P gap fill failed: ${formatCaughtError(exc)}`);
      });
      this._clientLog.debug(`_connectOnce exit: elapsed=${Date.now() - tStart}ms gateway=${gatewayUrl}, aid=${this._aid ?? ''}`);
    } catch (err) {
      this._state = prevState === 'connected' ? 'disconnected' : 'idle';
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
  async initV2Session(): Promise<void> {
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

    this._safeAsync(this._v2AutoConfirmPendingProposals());
  }

  private async _getV2SenderPubDer(fromAid: string, senderDeviceId: string): Promise<Uint8Array | null> {
    const session = this._v2Session;
    if (!session || !fromAid) return null;
    let senderPubDer = session.getPeerIK(fromAid, senderDeviceId);
    if (senderPubDer) return senderPubDer;

    try {
      const bs = await this.call('message.v2.bootstrap', { peer_aid: fromAid }) as Record<string, unknown>;
      const peers = (Array.isArray(bs?.peer_devices) ? bs.peer_devices : []) as Array<Record<string, unknown>>;
      for (const dev of peers) {
        const devId = String(dev.device_id ?? dev.owner_device_id ?? '');
        const ikPk = String(dev.ik_pk ?? '');
        if (!devId || !ikPk) continue;
        session.cachePeerIK(fromAid, devId, _v2B64ToBytes(ikPk));
      }
      senderPubDer = session.getPeerIK(fromAid, senderDeviceId);
      if (senderPubDer) return senderPubDer;
    } catch (exc) {
      this._clientLog.warn(`V2 decrypt: bootstrap for sender ${fromAid} failed: ${formatCaughtError(exc)}`);
    }

    try {
      const certPem = await this._fetchPeerCert(fromAid);
      const cert = new crypto.X509Certificate(certPem);
      const certPubDer = cert.publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
      senderPubDer = new Uint8Array(certPubDer);
      if (senderDeviceId) {
        session.cachePeerIK(fromAid, senderDeviceId, senderPubDer);
      }
      return senderPubDer;
    } catch (exc) {
      this._clientLog.warn(`V2 decrypt: CA fallback for ${fromAid} failed: ${formatCaughtError(exc)}`);
      return null;
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
    const cached = useCache ? this._v2BootstrapCache.get(to) : undefined;
    if (cached && Date.now() - cached.cachedAt < AUNClient.V2_BOOTSTRAP_TTL_MS) {
      peerDevices = cached.devices;
      auditRaw = cached.auditRecipients;
    } else {
      const bs = await this.call('message.v2.bootstrap', { peer_aid: to }) as Record<string, unknown>;
      peerDevices = (Array.isArray(bs?.peer_devices) ? bs.peer_devices : []) as Array<Record<string, unknown>>;
      auditRaw = (Array.isArray(bs?.audit_recipients) ? bs.audit_recipients : []) as Array<Record<string, unknown>>;
      if (peerDevices.length > 0) {
        this._v2BootstrapCache.set(to, {
          devices: peerDevices,
          auditRecipients: auditRaw,
          cachedAt: Date.now(),
        });
      }
    }
    if (peerDevices.length === 0) {
      throw new E2EEError(`V2 bootstrap: no devices found for ${to}`);
    }

    const targets: Target[] = [];
    for (const dev of peerDevices) {
      const ikPk = String(dev.ik_pk ?? '');
      if (!ikPk) continue;
      const devId = String(dev.device_id ?? dev.owner_device_id ?? '');
      const ikDer = _v2B64ToBytes(ikPk);
      const spkDer = dev.spk_pk ? _v2B64ToBytes(String(dev.spk_pk)) : undefined;
      session.cachePeerIK(to, devId, ikDer);
      targets.push({
        aid: to,
        deviceId: devId,
        role: 'peer',
        keySource: String(dev.key_source ?? 'peer_device_prekey'),
        ikPkDer: ikDer,
        spkPkDer: spkDer,
        spkId: String(dev.spk_id ?? ''),
      });
    }

    const auditTargets: Target[] = [];
    for (const dev of auditRaw) {
      const ikPk = String(dev.ik_pk ?? '');
      if (!ikPk) continue;
      auditTargets.push({
        aid: String(dev.aid ?? ''),
        deviceId: String(dev.device_id ?? ''),
        role: 'audit',
        keySource: String(dev.key_source ?? 'peer_device_prekey'),
        ikPkDer: _v2B64ToBytes(ikPk),
        spkPkDer: dev.spk_pk ? _v2B64ToBytes(String(dev.spk_pk)) : undefined,
        spkId: String(dev.spk_id ?? ''),
      });
    }

    // self-sync：给同 AID 其它在线/注册设备也 wrap 一份。
    if (this._aid && this._aid !== to) {
      try {
        const selfCached = this._v2BootstrapCache.get(this._aid);
        let selfDevices: Array<Record<string, unknown>> = [];
        if (selfCached && Date.now() - selfCached.cachedAt < AUNClient.V2_BOOTSTRAP_TTL_MS) {
          selfDevices = selfCached.devices;
        } else {
          const selfBs = await this.call('message.v2.bootstrap', { peer_aid: this._aid }) as Record<string, unknown>;
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
          const devId = String(dev.owner_device_id ?? dev.device_id ?? '');
          const ikPk = String(dev.ik_pk ?? '');
          if (!devId || devId === this._deviceId || !ikPk) continue;
          targets.push({
            aid: this._aid,
            deviceId: devId,
            role: 'self_sync',
            keySource: String(dev.key_source ?? 'peer_device_prekey'),
            ikPkDer: _v2B64ToBytes(ikPk),
            spkPkDer: dev.spk_pk ? _v2B64ToBytes(String(dev.spk_pk)) : undefined,
            spkId: String(dev.spk_id ?? ''),
          });
        }
      } catch (exc) {
        this._clientLog.debug(`V2 self-sync bootstrap failed (non-fatal): ${formatCaughtError(exc)}`);
      }
    }

    if (targets.length === 0) {
      throw new E2EEError(`V2 bootstrap: no usable devices found for ${to}`);
    }
    return encryptP2PMessage(
      session.getSenderIdentity(),
      { targets, auditRecipients: auditTargets },
      opts.payload,
      {
        messageId: opts.messageId,
        timestamp: opts.timestamp,
        protectedHeaders: opts.protectedHeaders,
        context: opts.context,
      },
    );
  }

  /** V2 P2P 加密发送，推测性缓存失败后刷新 bootstrap 重试一次。 */
  async sendV2(
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
      return await this.call('message.send', {
        to: toAid,
        payload: envelope as JsonObject,
        encrypt: false,
      });
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
  async pullV2(afterSeq: number = 0, limit: number = 50): Promise<Array<Record<string, unknown>>> {
    await this._ensureV2SessionReady('message.pull');
    const ns = this._aid ? `p2p:${this._aid}` : '';
    const effective = afterSeq || (ns ? this._seqTracker.getContiguousSeq(ns) : 0);
    const result = await this.call('message.v2.pull', { after_seq: effective, limit }) as Record<string, unknown>;
    const messages = (Array.isArray(result?.messages) ? result.messages : []) as Array<Record<string, unknown>>;
    const decrypted: Array<Record<string, unknown>> = [];
    const seqs = messages
      .map((msg) => Number(msg.seq ?? 0))
      .filter((seq) => Number.isFinite(seq) && seq > 0);
    const contigBefore = ns ? this._seqTracker.getContiguousSeq(ns) : 0;
    if (ns && seqs.length > 0 && seqs[0] > contigBefore) {
      this._seqTracker.forceContiguousSeq(ns, seqs[0]);
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

      const spkId = String(msg.spk_id ?? '');
      if (spkId && this._v2Session && !this._v2Session.isCurrentSPK(spkId)) {
        this._v2Session.trackOldSPKMaxSeq(spkId, seq);
      }
      const plaintext = await this._decryptV2Message(msg);
      if (plaintext === null) continue;
      if (ns) await this._publishPulledMessage('message.received', ns, seq, plaintext as EventPayload);
      else await this._publishAppEvent('message.received', plaintext as EventPayload);
      decrypted.push(plaintext);
    }

    if (ns && seqs.length > 0) {
      const maxSeq = Math.max(...seqs);
      const contig = this._seqTracker.getContiguousSeq(ns);
      if (maxSeq > contig) {
        this._seqTracker.forceContiguousSeq(ns, maxSeq);
        await this._drainOrderedMessages(ns);
      }
      const ackSeq = this._seqTracker.getContiguousSeq(ns);
      if (ackSeq !== contigBefore) {
        this._saveSeqTrackerState();
      }
      if (ackSeq > 0 && ackSeq !== contigBefore) {
        this._safeAsync(this.ackV2(ackSeq).then(() => undefined));
      }
    }
    return decrypted;
  }

  /** V2 P2P ack，并触发旧 SPK 销毁自检。 */
  async ackV2(upToSeq?: number): Promise<unknown> {
    const ns = this._aid ? `p2p:${this._aid}` : '';
    const seq = Number(upToSeq ?? (ns ? this._seqTracker.getContiguousSeq(ns) : 0));
    if (!Number.isFinite(seq) || seq <= 0) return { acked: 0 };
    const raw = await this.call('message.v2.ack', { up_to_seq: seq });
    const result: JsonObject = isJsonObject(raw as JsonValue | object | null | undefined)
      ? { ...(raw as JsonObject) }
      : { result: raw as JsonValue };
    result.ack_seq = seq;
    result.success = true;
    if (Number(result.acked ?? 0) === 0) result.acked = seq;
    if (this._v2Session) {
      try {
        const destroyed = this._v2Session.maybeDestroyOldSPKs(seq);
        if (destroyed.length > 0) {
          this._clientLog.info(`V2 destroyed old SPKs after ack: ${destroyed.slice(0, 3).join(',')} (PFS)`);
        }
      } catch (exc) {
        this._clientLog.debug(`V2 SPK destroy failed (non-fatal): ${formatCaughtError(exc)}`);
      }
    }
    return result;
  }

  /** V2 Group 加密发送，推测性缓存失败后刷新 bootstrap 重试一次。 */
  async sendGroupV2(
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
      return await this.call('group.v2.send', {
        group_id: gid,
        envelope: envelope as JsonObject,
      });
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

    const cached = useCache ? this._v2BootstrapCache.get(cacheKey) : undefined;
    if (cached && Date.now() - cached.cachedAt < AUNClient.V2_BOOTSTRAP_TTL_MS) {
      allDevices = cached.devices;
      auditRecipientsRaw = cached.auditRecipients;
      epoch = cached.epoch ?? 0;
      stateCommitment = cached.stateCommitment ?? stateCommitment;
    } else {
      const bs = await this.call('group.v2.bootstrap', { group_id: groupId }) as Record<string, unknown>;
      allDevices = (Array.isArray(bs.devices) ? bs.devices : []) as Array<Record<string, unknown>>;
      auditRecipientsRaw = (Array.isArray(bs.audit_recipients) ? bs.audit_recipients : []) as Array<Record<string, unknown>>;
      epoch = Number(bs.epoch ?? 0) || 0;
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
      const devId = String(dev.device_id ?? '').trim();
      const ikPk = String(dev.ik_pk ?? '').trim();
      if (!devAid || !devId || !ikPk) continue;
      if (devAid === this._aid && devId === this._deviceId) continue;
      const role = devAid === this._aid ? 'self_sync' : 'member';
      targets.push({
        aid: devAid,
        deviceId: devId,
        role,
        keySource: String(dev.key_source ?? 'peer_device_prekey'),
        ikPkDer: _v2B64ToBytes(ikPk),
        spkPkDer: dev.spk_pk ? _v2B64ToBytes(String(dev.spk_pk)) : undefined,
        spkId: String(dev.spk_id ?? ''),
      });
    }
    if (targets.length === 0) {
      throw new E2EEError(`V2 group: no target devices for group ${groupId}`);
    }

    for (const dev of auditRecipientsRaw) {
      const ikPk = String(dev.ik_pk ?? '').trim();
      if (!ikPk) continue;
      targets.push({
        aid: String(dev.aid ?? ''),
        deviceId: String(dev.device_id ?? ''),
        role: 'audit',
        keySource: String(dev.key_source ?? 'peer_device_prekey'),
        ikPkDer: _v2B64ToBytes(ikPk),
        spkPkDer: dev.spk_pk ? _v2B64ToBytes(String(dev.spk_pk)) : undefined,
        spkId: String(dev.spk_id ?? ''),
      });
    }

    return encryptGroupMessage(
      session.getSenderIdentity(),
      groupId,
      epoch,
      targets,
      opts.payload,
      {
        messageId: opts.messageId,
        timestamp: opts.timestamp,
        protectedHeaders: opts.protectedHeaders,
        context: opts.context,
      },
      stateCommitment,
    );
  }

  private async _pullGroupV2Internal(params: { group_id: string; after_seq: number; limit: number }): Promise<void> {
    await this.pullGroupV2(params.group_id, params.after_seq, params.limit);
  }

  /** V2 Group 拉取并解密；直接方法返回消息数组，call("group.pull") 会包装为 {messages}. */
  async pullGroupV2(groupId: string, afterSeq: number = 0, limit: number = 50): Promise<Array<Record<string, unknown>>> {
    await this._ensureV2SessionReady('group.pull');
    const gid = normalizeGroupId(groupId) || String(groupId ?? '').trim();
    if (!gid) throw new ValidationError('group.pull requires group_id');
    const ns = `group:${gid}`;
    const effective = afterSeq || this._seqTracker.getContiguousSeq(ns);
    const result = await this.call('group.v2.pull', {
      group_id: gid,
      after_seq: effective,
      limit,
    }) as Record<string, unknown>;
    const messages = (Array.isArray(result.messages) ? result.messages : []) as Array<Record<string, unknown>>;
    const decrypted: Array<Record<string, unknown>> = [];
    const seqs = messages
      .map((msg) => Number(msg.seq ?? 0))
      .filter((seq) => Number.isFinite(seq) && seq > 0);
    const contigBefore = this._seqTracker.getContiguousSeq(ns);
    if (seqs.length > 0 && seqs[0] > contigBefore) {
      this._seqTracker.forceContiguousSeq(ns, seqs[0]);
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
      plaintext.group_id = gid;
      await this._publishPulledMessage('group.message_created', ns, seq, plaintext as EventPayload);
      decrypted.push(plaintext);
    }

    if (seqs.length > 0) {
      const maxSeq = Math.max(...seqs);
      const contig = this._seqTracker.getContiguousSeq(ns);
      if (maxSeq > contig) {
        this._seqTracker.forceContiguousSeq(ns, maxSeq);
        await this._drainOrderedMessages(ns);
      }
    }
    const ackSeq = this._seqTracker.getContiguousSeq(ns);
    if (ackSeq !== contigBefore) {
      this._saveSeqTrackerState();
    }
    if (ackSeq > 0 && ackSeq !== contigBefore) {
      this._safeAsync(this.ackGroupV2(gid, ackSeq).then(() => undefined));
    }
    return decrypted;
  }

  /** V2 Group ack。 */
  async ackGroupV2(groupId: string, upToSeq?: number): Promise<unknown> {
    const gid = normalizeGroupId(groupId) || String(groupId ?? '').trim();
    if (!gid) throw new ValidationError('group.ack_messages requires group_id');
    const ns = `group:${gid}`;
    const seq = Number(upToSeq ?? this._seqTracker.getContiguousSeq(ns));
    if (!Number.isFinite(seq) || seq <= 0) return { acked: 0 };
    return await this.call('group.v2.ack', { group_id: gid, up_to_seq: seq });
  }

  /** 解密单条 V2 pull 消息。失败返回 null 并发布 undecryptable。 */
  private async _decryptV2Message(msg: Record<string, unknown>): Promise<Record<string, unknown> | null> {
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

    let spkId = '';
    if (isJsonObject(envelope.recipient as JsonValue | object | null | undefined)) {
      spkId = String((envelope.recipient as JsonObject).spk_id ?? '');
    } else if (Array.isArray(envelope.recipients)) {
      spkId = String(msg.spk_id ?? '');
    }
    const { ikPriv, spkPriv } = session.getDecryptKeys(spkId);
    const fromAid = String(msg.from_aid ?? '');
    const aad = isJsonObject(envelope.aad as JsonValue | object | null | undefined) ? envelope.aad as JsonObject : {};
    const senderDeviceId = String(aad.from_device ?? '');
    const senderPubDer = await this._getV2SenderPubDer(fromAid, senderDeviceId);
    if (!senderPubDer) {
      await this._dispatcher.publish('message.undecryptable', {
        message_id: String(msg.message_id ?? ''),
        from: fromAid,
        seq: msg.seq as JsonValue,
        _decrypt_error: 'sender_ik_not_found',
      });
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
      await this._dispatcher.publish('message.undecryptable', {
        message_id: String(msg.message_id ?? ''),
        from: fromAid,
        seq: msg.seq as JsonValue,
        _decrypt_error: String(formatCaughtError(exc)),
      });
      return null;
    }
    if (plaintext === null) return null;

    if (session.isCurrentSPK(spkId)) {
      this._safeAsync(session.rotateSPK(this._v2CallFn()).then(() => {
        this._clientLog.debug(`V2 SPK rotated after consumption: aid=${this._aid ?? ''}`);
      }));
    }

    const suite = String(envelope.suite ?? '');
    return {
      message_id: String(msg.message_id ?? ''),
      from: fromAid,
      to: this._aid ?? '',
      seq: msg.seq as JsonValue,
      t_server: msg.t_server as JsonValue,
      payload: plaintext,
      encrypted: true,
      e2ee: {
        version: 'v2',
        suite,
        encryption_mode: `v2_${suite || 'unknown'}`,
        forward_secrecy: true,
      },
    };
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

    const attempt = async (useCache: boolean): Promise<RpcResult> => {
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
      return await this._transport.call('message.thought.put', sendParams);
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

    const attempt = async (useCache: boolean): Promise<RpcResult> => {
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
      return await this._transport.call('group.thought.put', sendParams);
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
    if (Array.isArray(envelope.recipients)) {
      for (const row of envelope.recipients) {
        if (!Array.isArray(row) || row.length < 8) continue;
        if (String(row[0] ?? '') === this._aid && String(row[1] ?? '') === this._deviceId) {
          spkId = String(row[5] ?? '');
          break;
        }
      }
    } else if (isJsonObject(envelope.recipient as JsonValue | object | null | undefined)) {
      spkId = String((envelope.recipient as JsonObject).spk_id ?? '');
    }
    const { ikPriv, spkPriv } = session.getDecryptKeys(spkId);
    const aad = isJsonObject(envelope.aad as JsonValue | object | null | undefined) ? envelope.aad as JsonObject : {};
    const fromAid = String(opts.fromAid || aad.from || '').trim();
    const senderDeviceId = String(aad.from_device ?? '');
    const senderPubDer = await this._getV2SenderPubDer(fromAid, senderDeviceId);
    if (!senderPubDer) {
      this._clientLog.warn(`V2 thought decrypt: no sender IK for ${fromAid} device=${senderDeviceId}`);
      return null;
    }
    try {
      return decryptMessage(
        envelope,
        this._aid ?? '',
        this._deviceId,
        ikPriv,
        spkPriv,
        senderPubDer,
      );
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
        .update(actorAid, 'utf-8')
        .update(Buffer.from([0]))
        .update(signPayload, 'utf-8')
        .update(Buffer.from([0]))
        .update(sigBytes)
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

      const bootstrapResp = await this.call('group.v2.bootstrap', { group_id: groupId });
      const devices = isJsonObject(bootstrapResp) && Array.isArray(bootstrapResp.devices)
        ? bootstrapResp.devices.filter(isJsonObject) as JsonObject[]
        : [];
      const candidates: string[] = [];
      for (const dev of devices) {
        const aid = String(dev.aid ?? '').trim();
        const deviceId = String(dev.device_id ?? '').trim();
        if (aid && deviceId && onlineAdminAids.has(aid)) {
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

      const delayMs = this._v2LeaderDelayMs(`${groupId}\x00${myKey}`);
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

      const bootstrapResp = await this.call('group.v2.bootstrap', { group_id: groupId });
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

  private async _onV2PushNotification(_data: EventPayload): Promise<void> {
    if (!this._v2Session) return;
    if (this._v2PullInflight) {
      this._v2PullPending = true;
      return;
    }
    this._v2PullInflight = true;
    try {
      do {
        this._v2PullPending = false;
        await this.pullV2();
      } while (this._v2PullPending);
    } catch (exc) {
      this._clientLog.warn(`V2 push auto-pull failed: ${formatCaughtError(exc)}`);
    } finally {
      this._v2PullInflight = false;
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

  private async _onRawGroupV2MessageCreated(data: EventPayload): Promise<void> {
    if (!isJsonObject(data) || !this._v2Session) return;
    const groupId = String(data.group_id ?? '').trim();
    const seq = Number(data.seq ?? 0);
    if (!groupId || !Number.isFinite(seq) || seq <= 0) return;
    const ns = `group:${groupId}`;
    if (this._pushedSeqs.get(ns)?.has(seq)) return;
    const afterSeq = this._seqTracker.getContiguousSeq(ns);
    const dedupKey = `v2_group_push:${groupId}:${afterSeq}`;
    if (this._gapFillDone.has(dedupKey)) return;
    this._gapFillDone.set(dedupKey, Date.now());
    try {
      await this.pullGroupV2(groupId, afterSeq, 50);
    } catch (exc) {
      this._clientLog.warn(`V2 group push auto-pull failed: group=${groupId} err=${formatCaughtError(exc)}`);
    } finally {
      this._gapFillDone.delete(dedupKey);
    }
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

  /** 从参数中解析 Gateway URL */
  private _resolveGateway(params: ConnectParams): string {
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
    const gateway = String(params.gateway ?? '');
    if (!gateway) {
      throw new StateError('missing gateway in connect params');
    }
    return gateway;
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
  private _normalizeConnectParams(params: RpcParams): ConnectParams {
    const request: ConnectParams = { ...params };
    const accessToken = String(request.access_token ?? '');
    if (!accessToken) throw new StateError('connect requires non-empty access_token');
    const gateway = String(request.gateway ?? this._gatewayUrl ?? '');
    if (!gateway) throw new StateError('connect requires non-empty gateway');
    request.access_token = accessToken;
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
      if (this._closing || this._state !== 'connected') return;
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
    if (newInterval > 0 && this._state === 'connected' && !this._closing) {
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
        if (this._state !== 'connected' || !this._gatewayUrl) {
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

        if (this._closing || this._state !== 'connected' || !this._gatewayUrl) {
          scheduleNext();
          return;
        }
        try {
          identity = await this._auth.refreshCachedTokens(this._gatewayUrl!, identity!);
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
    // 缓存最近一次 disconnect 信息，让后续 connection.state(terminal_failed) 也能带 detail
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
    if (this._closing || this._state === 'closed') return;
    // 已在重连中则跳过，避免心跳超时和 transport 断线回调重复触发
    if (this._reconnectActive) return;
    this._clientLog.warn(`transport disconnected: closeCode=${closeCode ?? 'none'}, error=${error ? formatCaughtError(error) : 'none'}`);
    this._state = 'disconnected';
    this._stopBackgroundTasks();
    await this._dispatcher.publish('connection.state', { state: this._state, error });

    if (!this._sessionOptions.auto_reconnect) return;
    if (this._reconnectActive) return;
    // 不重连 close code（认证失败/权限错误/被踢等）或服务端通知断开：抑制重连
    if (this._serverKicked || (closeCode !== undefined && AUNClient._NO_RECONNECT_CODES.has(closeCode))) {
      this._state = 'terminal_failed';
      const reason = this._serverKicked ? 'server kicked' : `close code ${closeCode}`;
      this._clientLog.warn(`suppressing auto-reconnect: ${reason}`);
      const disconnectInfo = this._lastDisconnectInfo ?? {};
      const eventPayload: Record<string, any> = {
        state: this._state, error, reason,
      };
      // 把服务端附带的结构化 detail（如配额超限信息）也带给应用层
      if (disconnectInfo.detail && Object.keys(disconnectInfo.detail).length > 0) {
        eventPayload.detail = disconnectInfo.detail;
      }
      if (disconnectInfo.code !== undefined && disconnectInfo.code !== null) {
        eventPayload.code = disconnectInfo.code;
      }
      await this._dispatcher.publish('connection.state', eventPayload);
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
    let delay = clampReconnectDelayMs(
      serverInitiated ? 16_000 : Number(retry.initial_delay ?? 1.0) * 1000,
      serverInitiated ? 16_000 : RECONNECT_MIN_BASE_DELAY_MS,
      maxBaseDelay,
    );

    for (let attempt = 1; !this._reconnectAbort?.signal.aborted; attempt++) {
      if (this._closing) break;
      // max_attempts 检查在循环顶部，覆盖所有路径（含 health-fail）
      if (maxAttempts > 0 && attempt > maxAttempts) {
        this._state = 'terminal_failed';
        await this._dispatcher.publish('connection.state', {
          state: this._state,
          attempt: attempt - 1,
          reason: 'max_attempts_exhausted',
        });
        break;
      }

      this._state = 'reconnecting';
      await this._dispatcher.publish('connection.state', {
        state: this._state,
        attempt,
      });

      try {
        // 固定上限抖动：base=[1s, max_base]，delay=base+rand(0..max_base)。
        await this._sleep(reconnectSleepDelayMs(delay, maxBaseDelay));
        if (this._reconnectAbort?.signal.aborted || this._closing) break;

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
        this._reconnectActive = false;
        this._reconnectAbort = null;
        return;
      } catch (exc) {
        await this._dispatcher.publish('connection.error', {
          error: formatCaughtError(exc),
          attempt,
        });
        if (!AUNClient._shouldRetryReconnect(exc as Error)) {
          this._state = 'terminal_failed';
          await this._dispatcher.publish('connection.state', {
            state: this._state,
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
  async createNamedGroup(groupName: string, opts: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
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
  async bindGroupAid(groupId: string, groupName: string): Promise<Record<string, unknown>> {
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
