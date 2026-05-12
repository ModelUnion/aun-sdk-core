/**
 * AUNClient — AUN Core SDK 主客户端
 *
 * 完整实现，与 Python SDK client.py 对齐。
 * 功能：
 * - 连接/断线重连/关闭
 * - RPC 调用（含 E2EE 自动加解密编排）
 * - 事件自动解密管线（P2P + 群组）
 * - 后台任务（心跳、token 刷新、prekey 轮换、epoch 清理/轮换）
 * - 客户端签名（关键操作）
 * - 群组 E2EE 全自动编排（建群/加人/踢人/退出）
 */

import * as crypto from 'node:crypto';
import * as http from 'node:http';
import * as https from 'node:https';
import { join } from 'node:path';
import { URL } from 'node:url';

import { configFromMap, getDeviceId, normalizeInstanceId, type AUNConfig } from './config.js';
import { CryptoProvider } from './crypto.js';
import { GatewayDiscovery } from './discovery.js';
import { E2EEManager, type PrekeyMaterial, type ProtectedHeadersInput } from './e2ee.js';
import {
  GroupE2EEManager,
  computeMembershipCommitment,
  computeStateHash,
  storeGroupSecret,
  storeGroupSecretEpoch,
  buildKeyDistribution,
  buildKeyRequest,
  buildMembershipManifest,
  signMembershipManifest,
  verifyEpochChain,
} from './e2ee-group.js';
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
import { SQLiteBackup } from './keystore/sqlite-backup.js';

import { AuthNamespace } from './namespaces/auth.js';
import { CustodyNamespace } from './namespaces/custody.js';
import { MetaNamespace } from './namespaces/meta.js';
import { RPCTransport } from './transport.js';
import { AuthFlow } from './auth.js';
import { SeqTracker } from './seq-tracker.js';
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
}

interface AuthContext extends JsonObject {
  identity?: IdentityRecord;
  token?: string;
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

interface GroupDistribution extends JsonObject {
  to: string;
  payload: JsonObject;
}

interface UploadPrekeyResult extends JsonObject {
  ok?: boolean;
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
    call: 10.0,
    http: 30.0,
  },
};

const RECONNECT_MIN_BASE_DELAY_MS = 1_000;
const RECONNECT_MAX_BASE_DELAY_MS = 64_000;
const TOKEN_REFRESH_CHECK_INTERVAL_MS = 30_000;
const GROUP_ROTATION_LEASE_MS = 120_000;
const GROUP_ROTATION_RETRY_MAX_DELAY_MS = 300_000;
const PENDING_DECRYPT_LIMIT = 100;
const PUSHED_SEQS_LIMIT = 50_000;
const PENDING_ORDERED_LIMIT = 50_000;

// P1-23: 非幂等方法使用更长超时（35s），避免 SDK 10s 超时 < gateway 30s 处理时间
const NON_IDEMPOTENT_TIMEOUT_MS = 35_000;
const NON_IDEMPOTENT_METHODS = new Set([
  'message.send', 'group.send', 'group.create', 'group.invite',
  'group.kick', 'group.remove_member', 'group.leave', 'group.dissolve',
  'group.update_name', 'group.update_avatar', 'group.update_announcement',
  'group.update_settings', 'group.rotate_epoch',
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
  'group.e2ee.begin_rotation', 'group.e2ee.commit_rotation',
  'group.e2ee.abort_rotation',
  'group.ban', 'group.unban',
  'group.dissolve', 'group.suspend', 'group.resume',
]);

/** peer 证书缓存 TTL（1 小时） */
const PEER_CERT_CACHE_TTL = 3600;
const PEER_PREKEYS_CACHE_TTL = 3600;

// ── 内部类型 ──────────────────────────────────────────────────

interface CachedPeerCert {
  certPem: string;
  validatedAt: number;
  refreshAfter: number;
}

interface PeerPrekeyResponse {
  found: boolean;
  prekey?: PrekeyMaterial;
}

interface ConsumedPrekeyInfo {
  encryption_mode?: string;
  prekey_id?: string;
}

interface ConsumedPrekeyCarrier {
  e2ee?: ConsumedPrekeyInfo;
}

interface CachedPeerPrekeys {
  items: PrekeyMaterial[];
  expireAt: number;
}

const PREKEY_FALLBACK_DEVICE_ID = 'aun_device_id';

function isGroupServiceAid(value: JsonValue | object | undefined): boolean {
  const text = String(value ?? '').trim();
  if (!text.includes('.')) return false;
  const [name, ...issuerParts] = text.split('.');
  return name === 'group' && issuerParts.join('.').length > 0;
}

function isPeerPrekeyMaterial(value: JsonValue | object | undefined): value is PrekeyMaterial {
  if (!isJsonObject(value)) return false;
  const candidate = value as Partial<PrekeyMaterial>;
  return (
    typeof candidate.prekey_id === 'string'
    && typeof candidate.public_key === 'string'
    && typeof candidate.signature === 'string'
    && (candidate.created_at === undefined || typeof candidate.created_at === 'number')
  );
}

function isPeerPrekeyResponse(value: JsonValue | object | undefined): value is PeerPrekeyResponse {
  if (!isJsonObject(value)) return false;
  const candidate = value as Partial<PeerPrekeyResponse>;
  if (typeof candidate.found !== 'boolean') return false;
  return candidate.prekey === undefined || isPeerPrekeyMaterial(candidate.prekey);
}

function normalizePeerPrekeys(prekeys: Array<JsonValue | object | undefined>): PrekeyMaterial[] {
  const normalized: PrekeyMaterial[] = [];
  for (const item of prekeys) {
    if (!isPeerPrekeyMaterial(item)) continue;
    const prekeyId = item.prekey_id.trim();
    const publicKey = item.public_key.trim();
    const signature = item.signature.trim();
    if (!prekeyId || !publicKey || !signature) continue;
    const deviceId = String((item as JsonObject).device_id ?? '').trim();
    const certFingerprint = String(item.cert_fingerprint ?? '').trim().toLowerCase();
    const candidate: PrekeyMaterial = {
      ...item,
      prekey_id: prekeyId,
      public_key: publicKey,
      signature,
      device_id: deviceId,
    };
    if (certFingerprint) {
      candidate.cert_fingerprint = certFingerprint;
    } else {
      delete candidate.cert_fingerprint;
    }
    normalized.push(candidate);
  }
  if (normalized.length === 0) return [];
  if (normalized.length === 1) {
    if (!String(normalized[0].device_id ?? '').trim()) {
      normalized[0].device_id = PREKEY_FALLBACK_DEVICE_ID;
    }
    return normalized;
  }
  const seen = new Set<string>();
  const filtered: PrekeyMaterial[] = [];
  for (const item of normalized) {
    const deviceId = String(item.device_id ?? '').trim();
    if (!deviceId || deviceId === PREKEY_FALLBACK_DEVICE_ID || seen.has(deviceId)) continue;
    seen.add(deviceId);
    filtered.push(item);
  }
  return filtered;
}

/** 判断加密失败是否由过期的对端证书或 prekey 引起，可通过刷新缓存重试 */
function isRetryablePeerMaterialError(error: unknown): boolean {
  const localCode = String((error as any)?.localCode ?? (error as any)?.code ?? '').trim();
  if (localCode === 'PEER_CERT_FINGERPRINT_MISMATCH'
    || localCode === 'PREKEY_CERT_FINGERPRINT_MISMATCH'
    || localCode === 'PREKEY_SIGNATURE_VERIFY_FAILED') {
    return true;
  }
  const message = error instanceof Error ? error.message : String(error ?? '');
  return message.includes('peer cert fingerprint mismatch for ')
    || message.includes('prekey cert fingerprint mismatch')
    || message.includes('prekey 签名验证失败');
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

  /** E2EE 管理器 */
  private _e2ee: E2EEManager;

  /** 群组 E2EE 管理器 */
  private _groupE2ee: GroupE2EEManager;

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
  private _connectDeliveryMode: JsonObject;
  private _defaultConnectDeliveryMode: JsonObject;

  /** peer 证书缓存 */
  private _certCache: Map<string, CachedPeerCert> = new Map();
  private _peerPrekeysCache: Map<string, CachedPeerPrekeys> = new Map();
  private _prekeyReplenishInflight: Set<string> = new Set();
  private _prekeyReplenished: Set<string> = new Set();

  /** 消息序列号跟踪器（群消息 + P2P 空洞检测） */
  private _seqTracker: SeqTracker = new SeqTracker();
  private _seqTrackerContext: string | null = null;

  /** 惰性群同步：已同步过的 group_id 集合 */
  private _groupSynced: Set<string> = new Set();
  /** 惰性 P2P 同步：是否已同步过 */
  private _p2pSynced = false;

  /** 补洞去重：已完成/进行中的 key -> 开始时间戳，防止重复 pull 同一区间 */
  private _gapFillDone: Map<string, number> = new Map();
  /** 已发布到应用层的 seq 集合（按命名空间），补洞路径 publish 前检查以避免重复分发 */
  private _pushedSeqs: Map<string, Set<number>> = new Map();
  /** 已解密但因 seq 空洞暂缓发布的应用层消息（按 namespace -> seq） */
  private _pendingOrderedMsgs: Map<string, Map<number, { event: string; payload: EventPayload }>> = new Map();
  private _pendingDecryptMsgs: Map<string, JsonObject[]> = new Map();
  private _groupEpochRotationInflight: Set<string> = new Set();
  private _groupEpochRecoveryInflight: Map<string, Promise<boolean>> = new Map();
  private _groupMembershipRotationDone: Set<string> = new Set();
  /** 群密钥 backfill 去重：已完成/进行中的 key 集合，防止重复分发 */
  private _groupMemberKeyBackfillDone: Set<string> = new Set();
  private _groupEpochRotationRetryTimers: Map<string, ReturnType<typeof setTimeout>> = new Map();

  // ── 后台任务定时器 ──────────────────────────────────────────
  private _heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private _tokenRefreshTimer: ReturnType<typeof setTimeout> | null = null;
  private _tokenRefreshFailures = 0;
  private _prekeyRefreshTimer: ReturnType<typeof setInterval> | null = null;
  private _groupEpochCleanupTimer: ReturnType<typeof setInterval> | null = null;
  private _groupEpochRotateTimer: ReturnType<typeof setInterval> | null = null;
  private _cacheCleanupTimer: ReturnType<typeof setInterval> | null = null;
  private _reconnectActive = false;
  private _reconnectAbort: AbortController | null = null;
  private _serverKicked = false;
  private _logger!: AUNLogger;
  private _clientLog!: ModuleLogger;

  constructor(config?: RpcParams, debug = false) {
    const rawConfig: RpcParams = { ...(config ?? {}) };
    this._configModel = configFromMap(rawConfig);
    this.config = {
      aun_path: this._configModel.aunPath,
      root_ca_path: this._configModel.rootCaPath,
      seed_password: this._configModel.seedPassword,
    };

    this._dispatcher = new EventDispatcher();
    this._discovery = new GatewayDiscovery({ verifySsl: this._configModel.verifySsl });

    const defaultSQLiteBackup = new SQLiteBackup(join(this._configModel.aunPath, '.aun_backup', 'aun_backup.db'));
    const keystore = new FileKeyStore(
      this._configModel.aunPath,
      {
        encryptionSeed: this._configModel.seedPassword ?? undefined,
        sqliteBackup: defaultSQLiteBackup,
      },
    );
    this._keystore = keystore;
    this._deviceId = getDeviceId(this._configModel.aunPath);

    // 初始化 Logger（per-client 单例）
    const debugFlag = this._configModel.debug || debug;
    this._logger = new AUNLogger({
      debug: debugFlag,
      aunPath: this._configModel.aunPath,
    });
    this._clientLog = this._logger.for('aun_core.client');
    if (debugFlag) {
      this._clientLog.info(`AUNClient 初始化完成 (debug=true, aunPath=${this._configModel.aunPath})`);
    }

    this._slotId = '';
    this._connectDeliveryMode = normalizeDeliveryModeConfig({ mode: 'fanout' });
    this._defaultConnectDeliveryMode = { ...this._connectDeliveryMode };

    this._auth = new AuthFlow({
      keystore,
      crypto: new CryptoProvider(),
      aid: null,
      deviceId: this._deviceId,
      slotId: this._slotId,
      rootCaPath: this._configModel.rootCaPath ?? undefined,
      verifySsl: this._configModel.verifySsl,
      logger: this._logger.for('aun_core.auth'),
    });

    this._transport = new RPCTransport({
      eventDispatcher: this._dispatcher,
      timeout: 10_000,
      onDisconnect: (err, closeCode) => this._handleTransportDisconnect(err, closeCode),
      verifySsl: this._configModel.verifySsl,
      logger: this._logger.for('aun_core.transport'),
    });

    this._e2ee = new E2EEManager({
      identityFn: () => this._identity ?? {},
      deviceIdFn: () => this._deviceId,
      keystore,
      replayWindowSeconds: this._configModel.replayWindowSeconds,
    });

    this._groupE2ee = new GroupE2EEManager({
      identityFn: () => this._identity ?? {},
      keystore,
      senderCertResolver: (aid: string) => this._getVerifiedPeerCert(aid),
      initiatorCertResolver: (aid: string) => this._getVerifiedPeerCert(aid),
    });

    this.auth = new AuthNamespace(this);
    this.custody = new CustodyNamespace(this);
    this.meta = new MetaNamespace(this);
    // 内部订阅：推送消息自动解密后 re-publish 给用户
    this._dispatcher.subscribe('_raw.message.received', (data) => this._onRawMessageReceived(data));
    // 群组消息推送：自动解密后 re-publish
    this._dispatcher.subscribe('_raw.group.message_created', (data) => this._onRawGroupMessageCreated(data));
    // 群组变更事件：拦截处理成员变更触发的 epoch 轮换，然后透传
    this._dispatcher.subscribe('_raw.group.changed', (data) => this._onRawGroupChanged(data));
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

  /** 连接状态 */
  get state(): string {
    return this._state;
  }

  /** E2EE 管理器 */
  get e2ee(): E2EEManager {
    return this._e2ee;
  }

  /** 群组 E2EE 管理器 */
  get groupE2ee(): GroupE2EEManager {
    return this._groupE2ee;
  }

  /** 最近一次 gateway health check 结果，null 表示尚未检查 */
  get gatewayHealth(): boolean | null {
    return this._discovery.lastHealthy;
  }

  /** 向 gatewayUrl 的 /health 端点发送 GET 请求，检查网关可用性 */
  async checkGatewayHealth(gatewayUrl: string, timeout = 5_000): Promise<boolean> {
    return this._discovery.checkHealth(gatewayUrl, timeout);
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
    if (this._state !== 'idle' && this._state !== 'closed' && this._state !== 'disconnected') {
      throw new StateError(`connect not allowed in state ${this._state}`);
    }
    this._state = 'connecting';
    const params = { ...auth };
    if (options) Object.assign(params, options);
    const normalized = this._normalizeConnectParams(params);
    this._sessionParams = normalized;
    this._sessionOptions = this._buildSessionOptions(normalized);
    const callTimeoutSec = this._sessionOptions.timeouts.call;
    this._transport.setTimeout(
      callTimeoutSec != null ? callTimeoutSec * 1000 : 10_000,
    );
    this._closing = false;
    try {
      await this._connectOnce(normalized, false);
    } catch (err) {
      // 连接失败时回退状态，允许重试
      if (this._state === 'connecting' || this._state === 'authenticating') {
        this._state = 'disconnected';
      }
      throw err;
    }
  }

  /** 关闭连接 */
  async close(): Promise<void> {
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
      return;
    }
    await this._transport.close();
    const closableKeyStore = this._keystore as KeyStore & { close?: () => void };
    closableKeyStore.close?.();
    this._state = 'closed';
    this._logger.close();
    await this._dispatcher.publish('connection.state', { state: this._state });
    this._resetSeqTrackingState();
  }

  /**
   * 断开连接但不关闭客户端（可重新 connect，对齐 Python disconnect）。
   * disconnect 是可恢复的：停止心跳、关闭 WebSocket，但不清理 keystore 等状态。
   */
  async disconnect(): Promise<void> {
    // 若 close() 已在执行中，跳过 disconnect 避免竞态
    if (this._closing) return;
    if (this._state !== 'connected' && this._state !== 'reconnecting') return;
    this._saveSeqTrackerState();
    this._stopBackgroundTasks();
    this._stopReconnect();
    await this._transport.close();
    this._state = 'disconnected';
    await this._dispatcher.publish('connection.state', { state: this._state });
  }

  /**
   * 列出本地所有已存储的身份摘要（仅返回有有效私钥的 AID）。
   */
  listIdentities(): Array<{ aid: string; metadata?: Record<string, unknown> }> {
    const listFn = (this._keystore as KeyStore & {
      listIdentities?: () => string[];
    }).listIdentities;
    if (typeof listFn !== 'function') return [];
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
    return summaries;
  }

  // ── RPC ───────────────────────────────────────────────────

  /**
   * 发送 JSON-RPC 调用。
   * 自动处理内部方法限制、E2EE 加解密、客户端签名等。
   */
  async call(method: string, params?: RpcParams): Promise<RpcResult> {
    if (this._state !== 'connected') {
      throw new ConnectionError('client is not connected');
    }
    if (INTERNAL_ONLY_METHODS.has(method)) {
      throw new PermissionError(`method is internal_only: ${method}`);
    }

    const p = { ...(params ?? {}) };
    this._validateOutboundCall(method, p);
    this._injectMessageCursorContext(method, p);

    // group.* 方法注入 device_id（服务端用于多设备消息路由）
    if (method.startsWith('group.') && this._deviceId && p.device_id === undefined) {
      p.device_id = this._deviceId;
    }
    if (method.startsWith('group.') && p.slot_id === undefined) {
      p.slot_id = this._slotId;
    }

    // 自动加密：message.send 默认加密（encrypt 默认 True）
    if (method === 'message.send') {
      const encrypt = p.encrypt ?? true;
      delete p.encrypt;
      if (encrypt) {
        return await this._sendEncrypted(p);
      }
      delete p.protected_headers;
      delete p.headers;
    }

    // 自动加密：group.send 默认加密（encrypt 默认 True）
    if (method === 'group.send') {
      const encrypt = p.encrypt ?? true;
      delete p.encrypt;
      if (encrypt) {
        return await this._sendGroupEncrypted(p);
      }
      delete p.protected_headers;
      delete p.headers;
    }
    if (method === 'group.thought.put') {
      const encrypt = p.encrypt ?? true;
      delete p.encrypt;
      if (!encrypt) {
        throw new ValidationError('group.thought.put requires encrypt=true');
      }
      return await this._putGroupThoughtEncrypted(p);
    }
    if (method === 'message.thought.put') {
      const encrypt = p.encrypt ?? true;
      delete p.encrypt;
      if (!encrypt) {
        throw new ValidationError('message.thought.put requires encrypt=true');
      }
      return await this._putMessageThoughtEncrypted(p);
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

    // 自动解密：message.pull 返回的消息
    if (method === 'message.pull' && isJsonObject(result)) {
      const r = result;
      const messages = r.messages;
      const rawMessages = Array.isArray(messages) ? messages.filter(isJsonObject) as Message[] : [];
      if (rawMessages.length > 0) {
        r.messages = await this._decryptMessages(rawMessages);
      }
      if (this._aid) {
        const ns = `p2p:${this._aid}`;
        if (rawMessages.length > 0) {
          this._seqTracker.onPullResult(ns, rawMessages);
        }
        // ⚠️ 逻辑边界 L1/L3：P2P retention floor 通道 = server_ack_seq
        // 服务端在持久化/设备视图分支返回 server_ack_seq，客户端若 contiguous 落后必须 force 跳过
        // retention window 外的空洞。与 S2 [1,seq-1] 历史 gap 配合；若去掉 force，首条消息建的 gap 会
        // 永远悬挂触发无限 pull。临时消息淘汰走 ephemeral_earliest_available_seq（当前仅提示），与此互斥。
        const serverAck = Number(r.server_ack_seq ?? 0);
        if (serverAck > 0) {
          const contig = this._seqTracker.getContiguousSeq(ns);
          if (contig < serverAck) {
            this._clientLog.info(`message.pull retention-floor 推进: ns=${ns} contiguous=${contig} -> server_ack_seq=${serverAck}`);
            this._seqTracker.forceContiguousSeq(ns, serverAck);
          }
        }
        this._saveSeqTrackerState();
        // auto-ack contiguous_seq
        const contig = this._seqTracker.getContiguousSeq(ns);
        if (contig > 0 && (rawMessages.length > 0 || serverAck > 0)) {
          this._transport.call('message.ack', {
            seq: contig,
            device_id: this._deviceId,
            slot_id: this._slotId,
          }).catch((e) => { this._clientLog.debug(`message.pull auto-ack 失败: ${formatCaughtError(e)}`); });
        }
      }
    }

    // 自动解密：group.pull 返回的群消息
    if (method === 'group.pull' && isJsonObject(result)) {
      const r = result;
      const messages = r.messages;
      const rawMessages = Array.isArray(messages) ? messages.filter(isJsonObject) as Message[] : [];
      if (rawMessages.length > 0) {
        r.messages = await this._decryptGroupMessages(rawMessages);
      }
      const gid = (p.group_id ?? '') as string;
      if (gid) {
        const ns = `group:${gid}`;
        if (rawMessages.length > 0) {
          this._seqTracker.onPullResult(ns, rawMessages);
        }
        // ⚠️ 逻辑边界 L4：group retention floor 通道 = cursor.current_seq
        // 群路径目前无独立 earliest_available_seq 字段；若未来引入 group retention，需新增字段并同步更新此处。
        // 与 S2 [1,seq-1] 历史 gap 配合使用，force_contiguous_seq 是跳过空洞的唯一手段。
        const cursor = isJsonObject(r.cursor) ? r.cursor : null;
        if (cursor) {
          const serverAck = Number(cursor.current_seq ?? 0);
          if (serverAck > 0) {
            const contig = this._seqTracker.getContiguousSeq(ns);
            if (contig < serverAck) {
              this._clientLog.info(`group.pull retention-floor 推进: ns=${ns} contiguous=${contig} -> cursor.current_seq=${serverAck}`);
              this._seqTracker.forceContiguousSeq(ns, serverAck);
            }
          }
        }
        this._saveSeqTrackerState();
        // auto-ack contiguous_seq
        const contig = this._seqTracker.getContiguousSeq(ns);
        const shouldAck = rawMessages.length > 0 || (cursor !== null && Number(cursor.current_seq ?? 0) > 0);
        if (contig > 0 && shouldAck) {
          this._transport.call('group.ack_messages', {
            group_id: gid,
            msg_seq: contig,
            device_id: this._deviceId,
            slot_id: this._slotId,
          }).catch((e) => { this._clientLog.debug(`group.pull auto-ack 失败: group=${gid} ${formatCaughtError(e)}`); });
        }
      }
    }
    if (method === 'group.thought.get' && isJsonObject(result)) {
      result = await this._decryptGroupThoughts(result);
    }
    if (method === 'message.thought.get' && isJsonObject(result)) {
      result = await this._decryptMessageThoughts(result);
    }

    // ── Group E2EE 自动编排（必备能力，始终启用）────────
    {
      // 建群后自动创建 epoch（幂等：已有 secret 时跳过）
      if (method === 'group.create' && isJsonObject(result)) {
        const group = isJsonObject(result.group) ? result.group as GroupRecord : null;
        const gid = group ? String(group.group_id ?? '') : '';
        if (gid && this._aid && !this._groupE2ee.hasSecret(gid)) {
          try {
            this._groupE2ee.createEpoch(gid, [this._aid]);
            // 同步到服务端：将服务端 epoch 从 0 推到 1；必须在 group.create 返回前完成，
            // 否则调用方紧接着加成员时会让初始 rotation 因成员集变化而提交失败。
            await this._syncEpochToServer(gid);
          } catch (exc) {
            this._logE2eeError('create_epoch', gid, '', exc as Error);
          }
        }
      }

      // 入群类 RPC 的成员集变更统一由 group.changed 事件驱动 epoch 轮换。

    }


    // 成员集变更主要由 group.changed 事件驱动；RPC 成功返回路径做幂等兜底，避免事件丢失或延迟时不轮换。
    const membershipMethods = new Set([
      'group.add_member', 'group.kick', 'group.remove_member', 'group.leave',
      'group.review_join_request', 'group.batch_review_join_request',
      'group.use_invite_code', 'group.request_join',
    ]);
    if (membershipMethods.has(method) && isJsonObject(result) && !('error' in result)) {
      const groupId = this._extractGroupIdFromResult(result) || String(p.group_id ?? '');
      if (groupId && this._membershipRotationChanged(method, result)) {
        const expectedEpoch = this._membershipRotationExpectedEpoch(result);
        // 自加入方法（request_join/use_invite_code）需要 allowMember=true，
        // 因为新成员角色是 member，必须允许 member 参与 leader 选举。
        const allowMember = method === 'group.request_join' || method === 'group.use_invite_code';
        // P0-12: await rotation 完成（带超时兜底），确保后续 group.send 使用新 epoch
        const rotationPromise = this._maybeLeadRotateGroupEpoch(
          groupId,
          this._membershipRotationTriggerId(groupId, result),
          expectedEpoch,
          allowMember,
        );
        const timeoutPromise = new Promise<void>((resolve) => globalThis.setTimeout(resolve, 5000));
        await Promise.race([rotationPromise, timeoutPromise]).catch((exc) =>
          this._clientLog.warn(`membership RPC epoch rotation fallback failed: ${formatCaughtError(exc)}`),
        );
      }
    }

    return result;
  }

  // ── 便利方法 ──────────────────────────────────────────────

  /** 心跳检测 */
  async ping(params?: RpcParams): Promise<RpcResult> {
    return await this.call('meta.ping', params ?? {});
  }

  /** 获取服务端状态 */
  async status(params?: RpcParams): Promise<RpcResult> {
    return await this.call('meta.status', params ?? {});
  }

  /** 获取信任根证书列表 */
  async trustRoots(params?: RpcParams): Promise<RpcResult> {
    return await this.call('meta.trust_roots', params ?? {});
  }

  // ── 事件 ──────────────────────────────────────────────────

  /** 订阅事件 */
  on(event: string, handler: EventHandler): Subscription {
    return this._dispatcher.subscribe(event, handler);
  }

  /** P2-13: 取消订阅事件（对齐 Python/JS off 方法） */
  off(event: string, handler: EventHandler): void {
    this._dispatcher.unsubscribe(event, handler);
  }

  // ── E2EE 加密发送 ────────────────────────────────────────

  private _protectedHeadersFromParams(params: RpcParams): ProtectedHeadersInput {
    const value = params.protected_headers ?? params.headers;
    if (value == null) return null;
    if (isJsonObject(value)) return value;
    if (typeof value === 'object' && typeof (value as { toObject?: () => unknown }).toObject === 'function') {
      return value as unknown as ProtectedHeadersInput;
    }
    return null;
  }

  /** 自动加密并发送 P2P 消息 */
  private async _sendEncrypted(params: RpcParams): Promise<RpcResult> {
    const toAid = String(params.to ?? '');
    this._validateMessageRecipient(toAid);
    const payload = isJsonObject(params.payload) ? params.payload : null;
    const messageId = String(params.message_id ?? '') || crypto.randomUUID();
    const timestamp = (params.timestamp as number) ?? Date.now();
    if (payload === null) {
      throw new ValidationError('message.send payload must be an object when encrypt=true');
    }
    const persistRequired = Boolean(params.persist_required || params.durable);
    const protectedHeaders = this._protectedHeadersFromParams(params);

    // 惰性同步：首次发送 P2P 消息时先 pull 一次
    if (!this._p2pSynced) {
      await this._lazySyncP2p();
    }

    // 内部发送逻辑，refreshPeerMaterial=true 时强制清缓存重新拉取对端材料
    const sendAttempt = async (refreshPeerMaterial = false): Promise<RpcResult> => {
      const recipientPrekeys = refreshPeerMaterial
        ? await this._refreshPeerPrekeys(toAid)
        : await this._fetchPeerPrekeys(toAid);
      const selfSyncCopies = await this._buildSelfSyncCopies({
        logicalToAid: toAid,
        payload,
        messageId,
        timestamp,
        protectedHeaders,
      });

      // 多设备过滤：只保留有有效 device_id 的可路由 prekey，
      // 占位符 PREKEY_FALLBACK_DEVICE_ID 表示服务端未分配真实设备 ID，不可用于多设备路由
      const routablePrekeys = recipientPrekeys.filter(pk => {
        const did = String((pk as JsonObject).device_id ?? '').trim();
        return did && did !== PREKEY_FALLBACK_DEVICE_ID;
      });
      const canUseMultiDevice = routablePrekeys.length > 0
        && (routablePrekeys.length > 1 || selfSyncCopies.length > 0);

      if (!canUseMultiDevice) {
        return await this._sendEncryptedSingle({
          toAid,
          payload,
          messageId,
          timestamp,
          prekey: routablePrekeys[0] ?? recipientPrekeys[0],
          persistRequired,
          protectedHeaders,
        });
      }

      const recipientCopies = await this._buildRecipientDeviceCopies({
        toAid,
        payload,
        messageId,
        timestamp,
        prekeys: routablePrekeys,
        protectedHeaders,
      });
      const sendParams: RpcParams = {
        to: toAid,
        payload: {
          type: 'e2ee.multi_device',
          logical_message_id: messageId,
          recipient_copies: recipientCopies,
          self_copies: selfSyncCopies,
        },
        type: 'e2ee.multi_device',
        encrypted: true,
        message_id: messageId,
        timestamp,
      };
      if (persistRequired) {
        sendParams.persist_required = true;
      }
      return await this._transport.call('message.send', sendParams);
    };

    // 首次尝试（使用缓存）；若对端证书/prekey 过期导致指纹不匹配，清缓存后重试一次
    try {
      return await sendAttempt(false);
    } catch (exc) {
      if (!isRetryablePeerMaterialError(exc)) throw exc;
      this._clientLog.warn(`peer cert/prekey mismatch for ${toAid}, refreshing and retrying once`);
    }
    return await sendAttempt(true);
  }


  private async _sendEncryptedSingle(opts: {
    toAid: string;
    payload: JsonObject;
    messageId: string;
    timestamp: number;
    prekey?: PrekeyMaterial | null;
    persistRequired?: boolean;
    protectedHeaders?: ProtectedHeadersInput;
  }): Promise<RpcResult> {
    let prekey = opts.prekey ?? null;
    if (!prekey) {
      prekey = await this._fetchPeerPrekey(opts.toAid);
    }
    const peerCertFingerprint = typeof prekey?.cert_fingerprint === 'string' ? prekey.cert_fingerprint : undefined;
    const peerCertPem = await this._fetchPeerCert(opts.toAid, peerCertFingerprint);
    const [envelope, encryptResult] = this._encryptCopyPayload({
      logicalToAid: opts.toAid,
      payload: opts.payload,
      peerCertPem,
      prekey,
      messageId: opts.messageId,
      timestamp: opts.timestamp,
      protectedHeaders: opts.protectedHeaders,
    });
    this._ensureEncryptResult(opts.toAid, encryptResult);

    const sendParams: RpcParams = {
      to: opts.toAid,
      payload: envelope,
      type: 'e2ee.encrypted',
      encrypted: true,
      message_id: opts.messageId,
      timestamp: opts.timestamp,
    };
    if (opts.persistRequired) {
      sendParams.persist_required = true;
    }
    return await this._transport.call('message.send', sendParams);
  }

  private async _buildRecipientDeviceCopies(opts: {
    toAid: string;
    payload: JsonObject;
    messageId: string;
    timestamp: number;
    prekeys: PrekeyMaterial[];
    protectedHeaders?: ProtectedHeadersInput;
  }): Promise<JsonObject[]> {
    const recipientCopies: JsonObject[] = [];
    const certCache = new Map<string, string>();
    for (const prekey of normalizePeerPrekeys(opts.prekeys)) {
      const deviceId = String((prekey as JsonObject).device_id ?? '').trim();
      const peerCertFingerprint = String(prekey.cert_fingerprint ?? '').trim().toLowerCase();
      const cacheKey = peerCertFingerprint || '__default__';
      let peerCertPem = certCache.get(cacheKey);
      if (!peerCertPem) {
        peerCertPem = await this._fetchPeerCert(opts.toAid, peerCertFingerprint || undefined);
        certCache.set(cacheKey, peerCertPem);
      }
      const [envelope, encryptResult] = this._encryptCopyPayload({
        logicalToAid: opts.toAid,
        payload: opts.payload,
        peerCertPem,
        prekey,
        messageId: opts.messageId,
        timestamp: opts.timestamp,
        protectedHeaders: opts.protectedHeaders,
      });
      this._ensureEncryptResult(opts.toAid, encryptResult);
      recipientCopies.push({
        device_id: deviceId,
        envelope,
      });
    }
    if (recipientCopies.length === 0) {
      throw new E2EEError(`no recipient device copies generated for ${opts.toAid}`);
    }
    return recipientCopies;
  }

  private async _resolveSelfCopyPeerCert(certFingerprint?: string): Promise<string> {
    const myAid = this._aid;
    if (!myAid) {
      throw new E2EEError('self sync copy requires current aid');
    }
    const normalizedFingerprint = String(certFingerprint ?? '').trim().toLowerCase();
    const identityCert = typeof this._identity?.cert === 'string' ? this._identity.cert : '';
    if (identityCert) {
      const identityFingerprint = `sha256:${new crypto.X509Certificate(identityCert).fingerprint256.replace(/:/g, '').toLowerCase()}`;
      if (!normalizedFingerprint || identityFingerprint === normalizedFingerprint) {
        return identityCert;
      }
    }
    const localCert = this._keystore.loadCert(myAid, normalizedFingerprint || undefined);
    if (localCert) {
      if (!normalizedFingerprint) {
        return localCert;
      }
      const actualFingerprint = `sha256:${new crypto.X509Certificate(localCert).fingerprint256.replace(/:/g, '').toLowerCase()}`;
      if (actualFingerprint === normalizedFingerprint) {
        return localCert;
      }
    }
    return await this._fetchPeerCert(myAid, normalizedFingerprint || undefined);
  }

  private async _buildSelfSyncCopies(opts: {
    logicalToAid: string;
    payload: JsonObject;
    messageId: string;
    timestamp: number;
    protectedHeaders?: ProtectedHeadersInput;
  }): Promise<JsonObject[]> {
    const myAid = this._aid;
    if (!myAid) {
      return [];
    }
    const prekeys = normalizePeerPrekeys(await this._fetchPeerPrekeys(myAid));
    if (prekeys.length === 0) {
      return [];
    }
    const copies: JsonObject[] = [];
    for (const prekey of prekeys) {
      const deviceId = String((prekey as JsonObject).device_id ?? '').trim();
      if (deviceId === this._deviceId) {
        continue;
      }
      let peerCertPem: string;
      try {
        peerCertPem = await this._resolveSelfCopyPeerCert(
          String(prekey.cert_fingerprint ?? '').trim().toLowerCase() || undefined,
        );
      } catch (e) {
        // 旧设备的 prekey 可能携带已轮换的证书指纹，跳过该设备的自同步副本
        this._clientLog.warn(`self-sync 跳过设备 ${deviceId}: 证书解析失败 (${e})，可能是旧 prekey`);
        continue;
      }
      const [envelope, encryptResult] = this._encryptCopyPayload({
        logicalToAid: opts.logicalToAid,
        payload: opts.payload,
        peerCertPem,
        prekey,
        messageId: opts.messageId,
        timestamp: opts.timestamp,
        protectedHeaders: opts.protectedHeaders,
      });
      this._ensureEncryptResult(myAid, encryptResult);
      copies.push({
        device_id: deviceId,
        envelope,
      });
    }
    return copies;
  }

  private _encryptCopyPayload(opts: {
    logicalToAid: string;
    payload: JsonObject;
    peerCertPem: string;
    prekey?: PrekeyMaterial | null;
    messageId: string;
    timestamp: number;
    protectedHeaders?: ProtectedHeadersInput;
    context?: JsonObject | null;
  }): [JsonObject, JsonObject] {
    const [envelope, encryptResult] = this._e2ee.encryptOutbound(
      opts.logicalToAid,
      opts.payload,
      opts.peerCertPem,
      opts.prekey ?? null,
      opts.messageId,
      opts.timestamp,
      opts.protectedHeaders,
      opts.context ?? null,
    ) as [JsonObject, JsonObject];
    return [envelope, encryptResult];
  }

  private _ensureEncryptResult(toAid: string, encryptResult: JsonObject): void {
    if (!encryptResult.encrypted) {
      throw new E2EEError(`failed to encrypt message to ${toAid}`);
    }
    if (this._configModel.requireForwardSecrecy && !encryptResult.forward_secrecy) {
      throw new E2EEError(
        `forward secrecy required but unavailable for ${toAid} ` +
        `(mode=${encryptResult.mode})`,
      );
    }
    if (encryptResult.degraded) {
      this._dispatcher.publish('e2ee.degraded', {
        peer_aid: toAid,
        mode: encryptResult.mode,
        reason: encryptResult.degradation_reason,
      }).catch((exc) => {
        this._clientLog.warn(`发布 e2ee.degraded 事件失败: ${formatCaughtError(exc)}`);
      });
    }
  }

  /** 自动加密并发送群组消息 */
  private async _sendGroupEncrypted(params: RpcParams): Promise<RpcResult> {
    return await this._callGroupEncryptedRpc('group.send', params, {
      idField: 'message_id',
      idPrefix: 'gm',
    });
  }

  private async _putGroupThoughtEncrypted(params: RpcParams): Promise<RpcResult> {
    return await this._callGroupEncryptedRpc('group.thought.put', params, {
      idField: 'thought_id',
      idPrefix: 'gt',
      extraFields: ['context'],
    });
  }

  private async _putMessageThoughtEncrypted(params: RpcParams): Promise<RpcResult> {
    const toAid = String(params.to ?? '').trim();
    this._validateMessageRecipient(toAid);
    const payload = isJsonObject(params.payload) ? params.payload : null;
    if (!toAid) {
      throw new ValidationError('message.thought.put requires to');
    }
    if (payload === null) {
      throw new ValidationError('message.thought.put payload must be an object when encrypt=true');
    }
    const thoughtId = String(params.thought_id ?? '') || `mt-${crypto.randomUUID()}`;
    const timestamp = Number(params.timestamp ?? Date.now());
    const prekey = await this._fetchPeerPrekey(toAid);
    const peerCertFingerprint = typeof prekey?.cert_fingerprint === 'string' ? prekey.cert_fingerprint : undefined;
    const peerCertPem = await this._fetchPeerCert(toAid, peerCertFingerprint);
    const [envelope, encryptResult] = this._encryptCopyPayload({
      logicalToAid: toAid,
      payload,
      peerCertPem,
      prekey,
      messageId: thoughtId,
      timestamp,
      protectedHeaders: this._protectedHeadersFromParams(params),
      context: isJsonObject(params.context) ? params.context : null,
    });
    this._ensureEncryptResult(toAid, encryptResult);
    const sendParams: RpcParams = {
      to: toAid,
      payload: envelope,
      type: 'e2ee.encrypted',
      encrypted: true,
      thought_id: thoughtId,
      timestamp,
    };
    if ('context' in params) sendParams.context = params.context;
    this._signClientOperation('message.thought.put', sendParams);
    return await this._transport.call('message.thought.put', sendParams);
  }

  private async _callGroupEncryptedRpc(
    method: string,
    params: RpcParams,
    options: { idField: string; idPrefix: string; extraFields?: string[] },
  ): Promise<RpcResult> {
    let { sendParams, groupId } = await this._prepareGroupEncryptedRpcParams(method, params, options);
    for (let attempt = 0; attempt < 2; attempt += 1) {
      try {
        return await this._transport.call(method, sendParams);
      } catch (exc) {
        if (attempt === 0 && this._isRecoverableGroupEpochError(exc)) {
          this._clientLog.warn(`群 ${groupId} 调用 ${method} 时 epoch 已过旧，恢复密钥后重加密重试一次: ${formatCaughtError(exc)}`);
          ({ sendParams, groupId } = await this._prepareGroupEncryptedRpcParams(method, params, options, true));
          continue;
        }
        throw exc;
      }
    }
    throw new StateError(`${method} failed after epoch recovery retry: group=${groupId}`);
  }

  private async _prepareGroupEncryptedRpcParams(
    method: string,
    params: RpcParams,
    options: { idField: string; idPrefix: string; extraFields?: string[] },
    strictEpochReady = false,
  ): Promise<{ sendParams: RpcParams; groupId: string }> {
    const groupId = String(params.group_id ?? '');
    const payload = isJsonObject(params.payload) ? params.payload : null;
    if (!groupId) {
      throw new ValidationError(`${method} requires group_id`);
    }
    if (payload === null) {
      throw new ValidationError(`${method} payload must be an object when encrypt=true`);
    }

    if (!this._groupSynced.has(groupId)) {
      await this._lazySyncGroup(groupId);
    }

    await this._ensureGroupEpochReady(groupId, strictEpochReady);
    await this._waitForGroupMembershipEpochFloor(groupId, 2000);

    const epochResult = await this._committedGroupEpochState(groupId);
    const committedEpoch = Number(epochResult.committed_epoch ?? epochResult.epoch ?? 0);
    const operationId = String(params[options.idField] ?? '').trim()
      || `${options.idPrefix}-${crypto.randomUUID()}`;
    const timestamp = Number(params.timestamp ?? Date.now());
    const protectedHeaders = this._protectedHeadersFromParams(params);
    const context = method === 'group.thought.put' && isJsonObject(params.context)
      ? params.context
      : null;
    const envelope = committedEpoch > 0
      ? this._groupE2ee.encryptWithEpoch(
        groupId,
        await this._ensureCommittedGroupSecretForSend(groupId, committedEpoch, epochResult),
        payload,
        {
          messageId: operationId,
          timestamp,
          protectedHeaders,
          context,
        },
      )
      : await this._groupE2ee.encrypt(groupId, payload, {
        messageId: operationId,
        timestamp,
        protectedHeaders,
        context,
      });
    const sendParams: RpcParams = {
      group_id: groupId,
      payload: envelope,
      type: 'e2ee.group_encrypted',
      encrypted: true,
      [options.idField]: operationId,
      timestamp,
    };
    if (this._deviceId && sendParams.device_id === undefined) {
      sendParams.device_id = this._deviceId;
    }
    if (sendParams.slot_id === undefined) {
      sendParams.slot_id = this._slotId;
    }
    for (const field of options.extraFields ?? []) {
      if (params[field] !== undefined) {
        sendParams[field] = params[field];
      }
    }
    await this._signClientOperation(method, sendParams);
    return { sendParams, groupId };
  }

  /** 惰性同步：首次激活群时 pull 最近消息，建立 seq 基线 */
  private async _lazySyncGroup(groupId: string): Promise<void> {
    this._groupSynced.add(groupId);
    try {
      const ns = `group:${groupId}`;
      const afterSeq = this._seqTracker.getContiguousSeq(ns);
      const result = await this._transport.call('group.pull', {
        group_id: groupId,
        after_message_seq: afterSeq,
        limit: 200,
      });
      const messages = Array.isArray((result as JsonObject)?.messages) ? (result as JsonObject).messages as JsonObject[] : [];
      for (const msg of messages) {
        const seq = (msg as JsonObject)?.seq;
        if (seq != null) this._seqTracker.onMessageSeq(ns, Number(seq));
      }
      if (messages.length > 0) {
        this._saveSeqTrackerState();
        this._clientLog.info(`惰性同步群 ${groupId}: pull ${messages.length} 条消息, after_seq=${afterSeq}`);
      }
    } catch (exc) {
      this._clientLog.warn(`惰性同步群 ${groupId} 失败: ${formatCaughtError(exc)}`);
    }
  }

  /** 惰性同步：首次激活 P2P 通道时 pull 最近消息，建立 seq 基线 */
  private async _lazySyncP2p(): Promise<void> {
    this._p2pSynced = true;
    if (!this._aid) return;
    try {
      const ns = `p2p:${this._aid}`;
      const afterSeq = this._seqTracker.getContiguousSeq(ns);
      const result = await this._transport.call('message.pull', {
        after_seq: afterSeq,
        limit: 200,
      });
      const messages = Array.isArray((result as JsonObject)?.messages) ? (result as JsonObject).messages as JsonObject[] : [];
      for (const msg of messages) {
        const seq = (msg as JsonObject)?.seq;
        if (seq != null) this._seqTracker.onMessageSeq(ns, Number(seq));
      }
      if (messages.length > 0) {
        this._saveSeqTrackerState();
        this._clientLog.info(`惰性同步 P2P: pull ${messages.length} 条消息, after_seq=${afterSeq}`);
      }
    } catch (exc) {
      this._clientLog.warn(`惰性同步 P2P 失败: ${formatCaughtError(exc)}`);
    }
  }

  private _isGroupEpochTooOldError(exc: unknown): boolean {
    const text = String(exc).toLowerCase();
    return text.includes('e2ee epoch too old') || text.includes('epoch below sender membership floor');
  }

  private _isGroupEpochRotationPendingError(exc: unknown): boolean {
    const text = String(exc).toLowerCase();
    return text.includes('e2ee epoch rotation pending') || text.includes('e2ee epoch not committed');
  }

  private _isGroupEpochChangedDuringSendError(exc: unknown): boolean {
    return String(exc).toLowerCase().includes('e2ee epoch changed during send');
  }

  private _isRecoverableGroupEpochError(exc: unknown): boolean {
    return this._isGroupEpochTooOldError(exc)
      || this._isGroupEpochRotationPendingError(exc)
      || this._isGroupEpochChangedDuringSendError(exc);
  }

  private _groupKeyRecoveryCandidates(groupId: string, epochResult: JsonObject): string[] {
    const candidates: string[] = [];
    const add = (value: unknown): void => {
      if (typeof value !== 'string') return;
      const aid = value.trim();
      if (aid && aid !== this._aid && !candidates.includes(aid)) candidates.push(aid);
    };
    add(epochResult.rotated_by);
    add(epochResult.owner_aid);
    for (const key of ['recovery_candidates', 'admins', 'members']) {
      const values = epochResult[key];
      if (Array.isArray(values)) {
        for (const value of values) {
          if (typeof value === 'string') add(value);
          else if (isJsonObject(value)) add(value.aid);
        }
      }
    }
    const localMembers = this._groupE2ee.getMemberAids(groupId);
    for (const aid of localMembers) add(aid);
    return candidates;
  }

  private async _requestGroupKeyFrom(groupId: string, targetAid: string, epoch = 0): Promise<void> {
    try {
      const reqPayload = buildKeyRequest(groupId, epoch, this._aid || '');
      this._groupE2ee.rememberKeyRequest(reqPayload, targetAid);
      await this.call('message.send', {
        to: targetAid,
        payload: reqPayload,
        encrypt: true,
        persist_required: true,
      });
      this._clientLog.info(`已向 ${targetAid} 请求群 ${groupId} 的 epoch ${epoch} 密钥`);
    } catch (exc) {
      this._clientLog.warn(`向 ${targetAid} 请求群 ${groupId} 密钥失败: ${formatCaughtError(exc)}`);
    }
  }

  private async _requestGroupKeyFromCandidates(groupId: string, serverEpoch: number, epochResult: JsonObject): Promise<void> {
    for (const targetAid of this._groupKeyRecoveryCandidates(groupId, epochResult)) {
      await this._requestGroupKeyFrom(groupId, targetAid, serverEpoch);
    }
  }

  private async _recoverInitialGroupEpochIfNeeded(
    groupId: string,
    localEpoch: number,
    epochResult: JsonObject,
  ): Promise<JsonObject> {
    const serverEpoch = Number(epochResult.epoch ?? 0);
    if (serverEpoch !== 0 || localEpoch !== 1) return epochResult;
    const secretData = this._groupE2ee.loadSecret(groupId, 1) as JsonObject | null;
    if (!secretData || secretData.pending_rotation_id) return epochResult;
    this._clientLog.warn(`群 ${groupId} 检测到本地 epoch 1 已存在但服务端 epoch 仍为 0，尝试补同步初始 epoch`);
    await this._syncEpochToServer(groupId);
    try {
      const refreshed = await this.call('group.e2ee.get_epoch', { group_id: groupId });
      if (isJsonObject(refreshed)) return refreshed;
    } catch (exc) {
      this._clientLog.warn(`群 ${groupId} 初始 epoch 补同步后刷新服务端 epoch 失败: ${formatCaughtError(exc)}`);
    }
    return epochResult;
  }

  private async _ensureGroupEpochReady(groupId: string, strict: boolean): Promise<void> {
    const localEpoch = await this._groupE2ee.currentEpoch(groupId);
    const initialLocalEpoch = localEpoch ?? 0;
    let epochResult: JsonObject;
    try {
      const rawEpochResult = await this.call('group.e2ee.get_epoch', { group_id: groupId });
      if (!isJsonObject(rawEpochResult)) return;
      epochResult = rawEpochResult as JsonObject;
    } catch (exc) {
      if (strict) throw new StateError(`group ${groupId} failed to query server epoch before retry: ${formatCaughtError(exc)}`);
      this._clientLog.warn(`group ${groupId} epoch precheck failed: ${formatCaughtError(exc)}`);
      return;
    }
    let serverEpoch = Number(epochResult.committed_epoch ?? epochResult.epoch ?? 0);
    if (!Number.isFinite(serverEpoch)) return;
    const pending = isJsonObject(epochResult.pending_rotation) ? epochResult.pending_rotation : null;
    if (pending && !pending.expired) {
      const pendingBaseEpoch = Number(pending.base_epoch ?? serverEpoch);
      this._scheduleGroupRotationRetry(groupId, {
        reason: 'pending_recovery',
        triggerId: String(pending.rotation_id ?? ''),
        expectedEpoch: Number.isFinite(pendingBaseEpoch) ? pendingBaseEpoch : serverEpoch,
        pending,
      });
    }
    let effectiveLocalEpoch = initialLocalEpoch;
    if (serverEpoch === 0 && effectiveLocalEpoch === 1) {
      epochResult = await this._recoverInitialGroupEpochIfNeeded(groupId, effectiveLocalEpoch, epochResult);
      serverEpoch = Number(epochResult.committed_epoch ?? epochResult.epoch ?? 0);
      if (serverEpoch === 0) {
        throw new StateError(`group ${groupId} initial epoch sync has not completed; refuse to send with local epoch 1 while server epoch is 0`);
      }
    }
    if (serverEpoch <= effectiveLocalEpoch) {
      if (!strict || serverEpoch <= 0) return;
      const waitDeadline = Date.now() + 5000;
      while (Date.now() < waitDeadline) {
        await new Promise(resolve => setTimeout(resolve, 150));
        const refreshed = await this.call('group.e2ee.get_epoch', { group_id: groupId });
        const refreshedEpoch = isJsonObject(refreshed)
          ? Number(refreshed.committed_epoch ?? refreshed.epoch ?? 0)
          : 0;
        const currentLocal = await this._groupE2ee.currentEpoch(groupId);
        if (Number.isFinite(refreshedEpoch) && refreshedEpoch > serverEpoch) {
          epochResult = refreshed as JsonObject;
          serverEpoch = refreshedEpoch;
          effectiveLocalEpoch = currentLocal ?? 0;
          break;
        }
        if (currentLocal !== null && currentLocal > effectiveLocalEpoch) return;
      }
      if (serverEpoch <= effectiveLocalEpoch) {
        throw new StateError(`group ${groupId} epoch rotation has not completed`);
      }
    }

    this._clientLog.warn(`group ${groupId} local epoch=${effectiveLocalEpoch} < server epoch=${serverEpoch}; requesting key recovery`);
    await this._recoverGroupEpochKey(groupId, serverEpoch, '', 5000);

    const deadline = Date.now() + 5000;
    while (Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 150));
      const refreshedEpoch = await this._groupE2ee.currentEpoch(groupId);
      if (refreshedEpoch !== null && refreshedEpoch >= serverEpoch) return;
    }
    const refreshedEpoch = await this._groupE2ee.currentEpoch(groupId);
    throw new StateError(`group ${groupId} local epoch ${refreshedEpoch} is behind server epoch ${serverEpoch}; key recovery has not completed`);
  }

  private async _waitForGroupMembershipEpochFloor(groupId: string, timeoutMs: number): Promise<void> {
    void timeoutMs;
    while (true) {
      let committedEpoch = 0;
      let members: unknown = null;
      try {
        const epochResult = await this.call('group.e2ee.get_epoch', { group_id: groupId });
        committedEpoch = isJsonObject(epochResult) ? Number(epochResult.committed_epoch ?? epochResult.epoch ?? 0) : 0;
        const membersResult = await this.call('group.get_members', { group_id: groupId });
        members = isJsonObject(membersResult) ? membersResult.members : null;
      } catch (exc) {
        this._clientLog.debug(`群 ${groupId} 成员 epoch floor 预检跳过: ${formatCaughtError(exc)}`);
        return;
      }

      let maxMinReadEpoch = 0;
      if (Array.isArray(members)) {
        for (const member of members) {
          if (!isJsonObject(member)) continue;
          const value = Number(member.min_read_epoch ?? 0);
          if (Number.isFinite(value)) maxMinReadEpoch = Math.max(maxMinReadEpoch, value);
        }
      }
      if (maxMinReadEpoch <= committedEpoch) return;
      this._clientLog.warn(`群 ${groupId} 成员 min_read_epoch 高于 committed epoch，按 committed epoch 继续发送: committed=${committedEpoch} floor=${maxMinReadEpoch}`);
      return;
    }
  }

  private async _committedGroupEpochState(groupId: string): Promise<JsonObject> {
    try {
      const epochResult = await this.call('group.e2ee.get_epoch', { group_id: groupId });
      if (isJsonObject(epochResult)) return epochResult;
    } catch (exc) {
      this._clientLog.warn(`群 ${groupId} 查询 committed epoch 状态失败，回退本地 epoch: ${formatCaughtError(exc)}`);
    }
    const localEpoch = await this._groupE2ee.currentEpoch(groupId);
    return { epoch: localEpoch ?? 0, committed_epoch: localEpoch ?? 0 };
  }

  private _groupSecretMatchesCommittedRotation(secretData: JsonObject | null, committedRotation: JsonObject | null): boolean {
    if (!secretData) return false;
    const committedCommitment = committedRotation ? String(committedRotation.key_commitment ?? '').trim() : '';
    const localCommitment = String(secretData.commitment ?? '').trim();
    if (committedCommitment && committedCommitment !== localCommitment) return false;
    const pendingRotationId = String(secretData.pending_rotation_id ?? '').trim();
    if (!pendingRotationId) return true;
    if (!committedRotation) return false;
    if (String(committedRotation.rotation_id ?? '').trim() !== pendingRotationId) return false;
    return true;
  }

  private async _ensureCommittedGroupSecretForSend(
    groupId: string,
    committedEpoch: number,
    epochResult: JsonObject,
  ): Promise<number> {
    if (committedEpoch <= 0) return committedEpoch;
    let secretData = await this._groupE2ee.loadSecret(groupId, committedEpoch) as JsonObject | null;
    let committedRotation = isJsonObject(epochResult.committed_rotation) ? epochResult.committed_rotation : null;
    if (await this._committedRotationMembershipGap(groupId, committedEpoch, committedRotation)) {
      const allowMember = await this._groupAllowsMemberEpochRotation(groupId);
      this._clientLog.warn(`群 ${groupId} committed epoch ${committedEpoch} 的成员快照与当前成员不一致，触发成员变更轮换修复`);
      await this._maybeLeadRotateGroupEpoch(
        groupId,
        `${groupId}:committed_membership_gap:aid:${this._aid}:epoch:${committedEpoch}`,
        committedEpoch,
        allowMember,
      );
      const refreshed = await this._committedGroupEpochState(groupId);
      const refreshedCommittedEpoch = Number(refreshed.committed_epoch ?? refreshed.epoch ?? committedEpoch);
      if (Number.isFinite(refreshedCommittedEpoch) && refreshedCommittedEpoch > committedEpoch) {
        committedEpoch = refreshedCommittedEpoch;
        committedRotation = isJsonObject(refreshed.committed_rotation) ? refreshed.committed_rotation : null;
        secretData = await this._groupE2ee.loadSecret(groupId, committedEpoch) as JsonObject | null;
      }
      if (await this._committedRotationMembershipGap(groupId, committedEpoch, committedRotation)) {
        throw new StateError(`group ${groupId} committed membership is stale at epoch ${committedEpoch}; key rotation repair has not completed`);
      }
    }
    if (this._groupSecretMatchesCommittedRotation(secretData, committedRotation)) {
      return committedEpoch;
    }
    const pendingRotationId = secretData ? String(secretData.pending_rotation_id ?? '') : '';
    this._clientLog.warn(`群 ${groupId} epoch ${committedEpoch} 本地 pending key 未匹配服务端 committed rotation，先恢复密钥: local_rotation=${pendingRotationId || '-'}`);
    await this._recoverGroupEpochKey(groupId, committedEpoch, '', 5000);
    let refreshed = await this._committedGroupEpochState(groupId);
    const refreshedCommittedEpoch = Number(refreshed.committed_epoch ?? refreshed.epoch ?? committedEpoch);
    if (Number.isFinite(refreshedCommittedEpoch) && refreshedCommittedEpoch > committedEpoch) {
      committedEpoch = refreshedCommittedEpoch;
      await this._recoverGroupEpochKey(groupId, committedEpoch, '', 5000);
      refreshed = await this._committedGroupEpochState(groupId);
    }
    const refreshedRotation = isJsonObject(refreshed.committed_rotation) ? refreshed.committed_rotation : null;
    const refreshedSecret = await this._groupE2ee.loadSecret(groupId, committedEpoch) as JsonObject | null;
    if (!this._groupSecretMatchesCommittedRotation(refreshedSecret, refreshedRotation)) {
      throw new StateError(`group ${groupId} epoch ${committedEpoch} local key is pending or mismatched; refuse to send with uncommitted group key`);
    }
    return committedEpoch;
  }

  private async _committedRotationMembershipGap(
    groupId: string,
    committedEpoch: number,
    committedRotation: JsonObject | null,
  ): Promise<boolean> {
    if (!this._aid || committedEpoch <= 0 || !committedRotation) return false;
    const expectedMembers = Array.isArray(committedRotation.expected_members)
      ? committedRotation.expected_members.map((item) => String(item ?? '').trim()).filter(Boolean).sort()
      : [];
    if (expectedMembers.length === 0) return false;
    try {
      const membersResult = await this.call('group.get_members', { group_id: groupId });
      const rawMembers = isJsonObject(membersResult)
        ? (Array.isArray(membersResult.members) ? membersResult.members : membersResult.items)
        : [];
      if (!Array.isArray(rawMembers)) return false;
      const activeMembers = rawMembers
        .filter((item): item is JsonObject => isJsonObject(item))
        .map((item) => ({
          aid: String(item.aid ?? '').trim(),
          status: String(item.status ?? 'active').trim().toLowerCase(),
        }))
        .filter((item) => item.aid && ['', 'active'].includes(item.status))
        .map((item) => item.aid)
        .sort();
      if (!activeMembers.includes(this._aid) || activeMembers.length === 0) return false;
      if (activeMembers.join('\n') !== expectedMembers.join('\n')) {
        const missing = activeMembers.filter((aid) => !expectedMembers.includes(aid));
        const extra = expectedMembers.filter((aid) => !activeMembers.includes(aid));
        this._clientLog.info(`群 ${groupId} committed membership gap: epoch=${committedEpoch} missing=${JSON.stringify(missing)} extra=${JSON.stringify(extra)}`);
        return true;
      }
      return false;
    } catch (exc) {
      this._clientLog.debug(`查询当前成员失败，无法判断 committed membership gap: group=${groupId} err=${formatCaughtError(exc)}`);
      return false;
    }
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
    // 异步处理，不阻塞事件调度
    this._processAndPublishMessage(data).catch((exc) => {
      this._clientLog.warn(`P2P 消息解密失败: ${formatCaughtError(exc)}`);
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

    // 拦截 P2P 传输的群组密钥分发/请求/响应消息
    if (await this._tryHandleGroupKeyMessage(msg)) {
      return;
    }

    // P2P 空洞检测
    const seq = msg.seq as number | undefined;
    if (seq !== undefined && seq !== null && this._aid) {
      this._p2pSynced = true;  // 收到推送即视为已激活
      const ns = `p2p:${this._aid}`;
      const needPull = this._seqTracker.onMessageSeq(ns, seq);
      if (needPull) {
        this._fillP2pGap().catch(exc => this._clientLog.warn(`后台补洞触发失败: ${formatCaughtError(exc)}`));
      }
      // auto-ack contiguous_seq
      const contig = this._seqTracker.getContiguousSeq(ns);
      if (contig > 0) {
        this._transport.call('message.ack', {
          seq: contig,
          device_id: this._deviceId,
          slot_id: this._slotId,
        }).catch((e) => { this._clientLog.debug(`P2P auto-ack 失败: ${formatCaughtError(e)}`); });
      }
      // 即时持久化 cursor，异常断连后不回退
      this._saveSeqTrackerState();
    }

    const decrypted = await this._decryptSingleMessage(msg);
      if (seq !== undefined && seq !== null && this._aid) {
        const ns = `p2p:${this._aid}`;
        await this._publishOrderedMessage('message.received', ns, seq, decrypted);
      } else {
        await this._publishAppEvent('message.received', decrypted);
      }
  }

  /** 处理群组消息推送：自动解密后 re-publish */
  private async _onRawGroupMessageCreated(data: EventPayload): Promise<void> {
    this._processAndPublishGroupMessage(data).catch((exc) => {
      this._clientLog.warn(`群消息解密失败: ${formatCaughtError(exc)}`);
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
    const decrypted = await this._decryptGroupMessage(msg);

    // 只有带 payload 的真实消息，在同步解密/恢复尝试结束后才推进游标。
    if (groupId && seq !== undefined && seq !== null) {
      const ns = `group:${groupId}`;
      const needPull = this._seqTracker.onMessageSeq(ns, seq);
      if (needPull) {
        this._fillGroupGap(groupId).catch(exc => this._clientLog.warn(`后台补洞触发失败: ${formatCaughtError(exc)}`));
      }
      const contig = this._seqTracker.getContiguousSeq(ns);
      if (contig > 0) {
        this._transport.call('group.ack_messages', {
          group_id: groupId,
          msg_seq: contig,
          device_id: this._deviceId,
          slot_id: this._slotId,
        }).catch((e) => { this._clientLog.debug(`群消息 auto-ack 失败: group=${groupId} ${formatCaughtError(e)}`); });
      }
      this._saveSeqTrackerState();
    }

    // R3: 解密失败 → 不 publish 密文给应用层，入 pending 队列 + 发 undecryptable 事件
    const payloadForCheck = isJsonObject(msg.payload) ? msg.payload : null;
    if (payloadForCheck?.type === 'e2ee.group_encrypted' && !decrypted.e2ee) {
      if (groupId) this._enqueuePendingDecrypt(groupId, msg);
      await this._publishAppEvent('group.message_undecryptable', {
        message_id: msg.message_id,
        group_id: groupId,
        from: msg.from,
        seq,
        timestamp: msg.timestamp,
        _decrypt_error: 'group secret unavailable',
      });
      return;
    }

    if (groupId && seq !== undefined && seq !== null) {
      const nsKey = `group:${groupId}`;
      await this._publishOrderedMessage('group.message_created', nsKey, seq, decrypted);
    } else {
      await this._publishAppEvent('group.message_created', decrypted);
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
                await this._publishOrderedMessage('group.message_created', ns, s, msg);
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
      this._clientLog.debug(`自动 pull 群消息失败: ${formatCaughtError(exc)}`);
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
    try {
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
              if (pushed && s !== undefined && s !== null && pushed.has(s)) continue;
              if (s !== undefined && s !== null) {
                await this._publishOrderedMessage('group.message_created', ns, s, msg);
              } else {
                await this._publishAppEvent('group.message_created', msg);
              }
            }
          }
          this._prunePushedSeqs(ns);
        }
      }
    } catch (exc) {
      this._clientLog.warn(`群消息补洞失败: ${formatCaughtError(exc)}`);
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
    try {
      const result = await this.call('message.pull', {
        after_seq: afterSeq,
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
              if (pushed && s !== undefined && s !== null && pushed.has(s)) continue;
              if (s !== undefined && s !== null) {
                await this._publishOrderedMessage('message.received', ns, s, msg);
              } else {
                await this._publishAppEvent('message.received', msg);
              }
            }
          }
          this._prunePushedSeqs(ns);
        }
      }
    } catch (exc) {
      this._clientLog.warn(`P2P 消息补洞失败: ${formatCaughtError(exc)}`);
    } finally {
      this._gapFillDone.delete(dedupKey);
    }
  }

  /** 清理 pushedSeqs 中 <= contiguousSeq 的条目，防止无限增长 */
  private _prunePushedSeqs(ns: string): void {
    const pushed = this._pushedSeqs.get(ns);
    if (!pushed) return;
    const contig = this._seqTracker.getContiguousSeq(ns);
    for (const s of pushed) {
      if (s <= contig) pushed.delete(s);
    }
    if (pushed.size === 0) this._pushedSeqs.delete(ns);
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
    await this._dispatcher.publish(event, this._normalizePublishedMessagePayload(event, payload));
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

  /** 后台补齐群事件空洞 */
  private async _fillGroupEventGap(groupId: string): Promise<void> {
    const ns = `group_event:${groupId}`;
    const afterSeq = this._seqTracker.getContiguousSeq(ns);
    // 去重：同一 (group_evt:id:after_seq) 只补一次
    const dedupKey = `group_evt:${groupId}:${afterSeq}`;
    if (this._gapFillDone.has(dedupKey)) return;
    this._gapFillDone.set(dedupKey, Date.now());
    try {
      const result = await this.call('group.pull_events', {
        group_id: groupId,
        after_event_seq: afterSeq,
        device_id: this._deviceId,
        limit: 50,
      });
      if (isJsonObject(result)) {
        const events = result.events;
        if (Array.isArray(events)) {
          this._seqTracker.onPullResult(ns, events.filter(isJsonObject));
          const cursor = isJsonObject(result.cursor) ? result.cursor : null;
          const serverAck = cursor ? Number(cursor.current_seq ?? 0) : 0;
          if (serverAck > 0) {
            const contigBefore = this._seqTracker.getContiguousSeq(ns);
            if (contigBefore < serverAck) {
              this._clientLog.info(`group.pull_events retention-floor 推进: ns=${ns} contiguous=${contigBefore} -> cursor.current_seq=${serverAck}`);
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
            }).catch((e) => { this._clientLog.debug(`群事件 auto-ack 失败: group=${groupId} ${formatCaughtError(e)}`); });
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
            }
          }
        }
      }
    } catch (exc) {
      this._clientLog.warn(`群事件补洞失败: ${formatCaughtError(exc)}`);
    } finally {
      this._gapFillDone.delete(dedupKey);
    }
  }

  /**
   * 处理群组变更事件：透传给用户，并在成员离开/被踢时自动触发 epoch 轮换。
   * 按协议，轮换由剩余在线 admin/owner 负责。
   */
  private _membershipRotationExpectedEpoch(payload: JsonObject): number | null {
    for (const key of ['old_epoch', 'current_epoch', 'e2ee_epoch']) {
      const value = payload[key];
      if (value !== undefined && value !== null) {
        const n = Number(value);
        if (Number.isFinite(n)) return n;
      }
    }
    const group = payload.group;
    if (isJsonObject(group)) {
      for (const key of ['old_epoch', 'current_epoch', 'e2ee_epoch']) {
        const value = group[key];
        if (value !== undefined && value !== null) {
          const n = Number(value);
          if (Number.isFinite(n)) return n;
        }
      }
    }
    return null;
  }

  private _membershipRotationTriggerId(groupId: string, payload: JsonObject): string {
    let action = String(payload.action ?? '').trim();
    if (!action) {
      if (payload.removed_aid) action = 'member_removed';
      else if (payload.left_aid) action = 'member_left';
      else if (isJsonObject(payload.member)) action = 'member_added';
      else action = String(payload.status ?? payload.reason ?? 'membership_changed');
    }
    const group = isJsonObject(payload.group) ? payload.group : null;
    const eventSeq = payload.event_seq ?? payload.seq ?? group?.event_seq ?? '';
    const changedAids = new Set<string>();
    let changedAid = String(payload.aid ?? payload.removed_aid ?? payload.left_aid ?? payload.member_aid ?? payload.target_aid ?? '');
    if (changedAid) changedAids.add(changedAid);
    const member = isJsonObject(payload.member) ? payload.member : null;
    if (member?.aid) changedAids.add(String(member.aid));
    if (!changedAid && member) changedAid = String(member.aid ?? '');
    const request = isJsonObject(payload.request) ? payload.request : null;
    if (request?.aid) changedAids.add(String(request.aid));
    if (!changedAid && request) changedAid = String(request.aid ?? '');
    const inviteCode = isJsonObject(payload.invite_code) ? payload.invite_code : null;
    if (inviteCode?.used_by) changedAids.add(String(inviteCode.used_by));
    if (inviteCode?.aid) changedAids.add(String(inviteCode.aid));
    if (!changedAid && inviteCode) changedAid = String(inviteCode.used_by ?? inviteCode.aid ?? '');
    if (Array.isArray(payload.results)) {
      for (const item of payload.results) {
        if (!isJsonObject(item)) continue;
        const status = String(item.status ?? '').trim().toLowerCase();
        if (status !== 'approved' && item.approved !== true) continue;
        for (const key of ['aid', 'member_aid', 'target_aid']) {
          const value = item[key];
          if (value !== undefined && value !== null && String(value)) changedAids.add(String(value));
        }
        for (const key of ['member', 'request']) {
          const nested = isJsonObject(item[key]) ? item[key] : null;
          if (nested?.aid) changedAids.add(String(nested.aid));
        }
      }
    }
    const changedAidKey = Array.from(changedAids).filter(Boolean).sort().join(',');
    const expectedEpoch = this._membershipRotationExpectedEpoch(payload);
    if (changedAidKey && expectedEpoch !== null) return `${groupId}:${action}:aid:${changedAidKey}:epoch:${expectedEpoch}`;
    if (eventSeq !== undefined && eventSeq !== null && String(eventSeq) !== '') return `${groupId}:${action}:event:${String(eventSeq)}`;
    return `${groupId}:${action}:aid:${changedAidKey || changedAid || '-'}`;
  }

  private _membershipRotationChanged(method: string, payload: JsonObject): boolean {
    if (['group.add_member', 'group.kick', 'group.remove_member', 'group.leave'].includes(method)) {
      return true;
    }
    const status = String(payload.status ?? '').trim().toLowerCase();
    if (['group.use_invite_code', 'group.request_join'].includes(method)) {
      return ['joined', 'approved'].includes(status) || isJsonObject(payload.member);
    }
    if (method === 'group.review_join_request') {
      return status === 'approved' || payload.approved === true || isJsonObject(payload.member);
    }
    if (method === 'group.batch_review_join_request') {
      const results = payload.results;
      if (!Array.isArray(results)) return false;
      return results.some((item) => {
        if (!isJsonObject(item)) return false;
        const itemStatus = String(item.status ?? '').trim().toLowerCase();
        return itemStatus === 'approved' || item.approved === true;
      });
    }
    return false;
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
    if (isJsonObject(data)) {
      const d = data;
      // 验签：有 client_signature 就验，没有默认安全（H20: 严格 boolean）
      const cs = d.client_signature;
      if (cs && isJsonObject(cs)) {
        d._verified = await this._verifyEventSignatureAsync(d, cs);
      }
      await this._dispatcher.publish('group.changed', d);

      const groupId = String(d.group_id ?? '');

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
          }).catch((e) => { this._clientLog.debug(`群事件推送 auto-ack 失败: group=${groupId} ${formatCaughtError(e)}`); });
        }
      }

      // 仅在真实 event gap 时才触发补拉（补洞回来的事件不再触发新补洞）
      if (needPull && groupId && !d._from_gap_fill) {
        this._fillGroupEventGap(groupId).catch(exc => this._clientLog.warn(`后台补洞触发失败: ${formatCaughtError(exc)}`));
      }

      // 成员退出或被踢 → 剩余 admin/owner 自动补位轮换
      // H21: 避免 epoch 轮换风暴——所有剩余 admin 同时收到事件不能都发起轮换，
      // 否则 CAS 冲突激增。策略：本地 AID 为"排序最小 admin"时才发起，其他 admin
      // 叠加随机 jitter 作为超时兜底（本地最小 admin 失败时由下一位顶上）。
      if (d.action === 'member_left' || d.action === 'member_removed') {
        if (groupId) {
          {
            const expectedEpoch = this._membershipRotationExpectedEpoch(d);
            if (expectedEpoch === null) {
              this._clientLog.debug(`membership event without old_epoch skipped for epoch rotation: aid=${this._aid ?? ''} group=${groupId} action=${String(d.action ?? '')} event_seq=${String(d.event_seq ?? '')}`);
            } else {
              this._maybeLeadRotateGroupEpoch(groupId, this._membershipRotationTriggerId(groupId, d), expectedEpoch).catch((exc) =>
                this._logE2eeError('rotate_epoch', groupId, '', exc as Error),
              );
            }
          }
        }
      }

      // 成员加入：按 action 区分策略
      // - member_added / join_approved（私密群/审批群）：admin 必然在线，立即轮换
      // - joined / invite_code_used（开放群/邀请码群）：新成员先恢复 committed_epoch，延迟轮换
      if (['member_added', 'joined', 'join_approved', 'invite_code_used'].includes(String(d.action ?? ''))) {
        if (groupId) {
          {
            const action = String(d.action ?? '');
            const expectedEpoch = this._membershipRotationExpectedEpoch(d);
            const joinedAids = this._joinedMemberAidsFromPayload(d);
            const isSelfJoining = joinedAids.includes(this._aid ?? '') && (action === 'joined' || action === 'invite_code_used');
            this._clientLog.warn(`DEBUG: group.changed action=${action} groupId=${groupId} joinedAids=${JSON.stringify(joinedAids)} myAid=${this._aid} isSelfJoining=${String(isSelfJoining)} expectedEpoch=${String(expectedEpoch)}`);

            if (isSelfJoining || (action === 'joined' || action === 'invite_code_used')) {
              // open/invite_code 群：所有在线成员都参与延迟轮换
              // 新成员自己延迟更长，优先让其他在线成员先轮换
              const triggerId = this._membershipRotationTriggerId(groupId, d);
              if (!isSelfJoining) {
                this._maybeBackfillKeyToJoinedMember(groupId, d, triggerId).catch((exc) =>
                  this._logE2eeError('backfill_key', groupId, '', exc as Error),
                );
              }
              if (expectedEpoch !== null) {
                const delay = isSelfJoining ? AUNClient._SELF_JOIN_ROTATION_DELAY_MS : undefined;
                this._delayedRotateAfterJoin(groupId, triggerId, expectedEpoch, true, delay).catch((exc) =>
                  this._logE2eeError('rotate_epoch', groupId, '', exc as Error),
                );
              }
            } else {
              // member_added / join_approved：立即轮换
              if (expectedEpoch === null) {
                const triggerId = this._membershipRotationTriggerId(groupId, d);
                this._maybeBackfillKeyToJoinedMember(groupId, d, triggerId).catch((exc) =>
                  this._logE2eeError('backfill_key', groupId, '', exc as Error),
                );
              } else {
                this._maybeLeadRotateGroupEpoch(groupId, this._membershipRotationTriggerId(groupId, d), expectedEpoch).catch((exc) =>
                  this._logE2eeError('rotate_epoch', groupId, '', exc as Error),
                );
              }
            }
          }
        }
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
  }

  /**
   * 处理 event/group.state_committed：验证 state_hash 链并更新本地存储。
   * 当链断裂时回源 group.get_state，并对回源结果做本地 hash 重算验证。
   */
  private async _onGroupStateCommitted(data: EventPayload): Promise<void> {
    if (!isJsonObject(data)) return;
    const d = data;
    const groupId = String(d.group_id ?? '').trim();
    if (!groupId) return;

    // 提交者签名验证（兼容旧版：无签名时继续）
    const cs = d.client_signature;
    if (cs && isJsonObject(cs)) {
      const verified = await this._verifyEventSignatureAsync(d, cs);
      if (verified === false) {
        this._clientLog.warn(`state_committed 提交者签名验证失败 group=${groupId}`);
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
      this._clientLog.warn(`state_hash 链不连续 group=${groupId} local_sv=${localState.state_version} event_sv=${stateVersion}`);
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
              this._clientLog.warn(`回源 state_hash 验证失败 group=${groupId} sv=${sv} expected=${sHash} got=${computed}`);
              return;
            }
          }
          const saveFn = this._keystore.saveGroupState;
          if (saveFn) {
            saveFn.call(this._keystore, groupId, sv, sHash, sEpoch, sMembersJson || membershipSnapshot, sPolicyJson || policySnapshot);
          }
        }
      } catch (exc) {
        this._clientLog.warn(`state 回源失败 group=${groupId}: ${formatCaughtError(exc)}`);
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
      this._clientLog.warn(`state_hash 重算不匹配 group=${groupId} sv=${stateVersion} expected=${stateHash} got=${computed}`);
      return;
    }

    // 3. 更新本地存储
    const saveFn = this._keystore.saveGroupState;
    if (saveFn) {
      saveFn.call(this._keystore, groupId, stateVersion, stateHash, keyEpoch, membershipSnapshot, policySnapshot);
    }
  }

  /**
   * 成员退出/被踢后，判断本地是否为 leader admin 并发起 epoch 轮换。
   * 避免所有剩余 admin 同时触发 `_rotateGroupEpoch` 造成 CAS 风暴。
   */
  private async _maybeLeadRotateGroupEpoch(groupId: string, triggerId = '', expectedEpoch: number | null = null, allowMember = false): Promise<void> {
    const myAid = this._aid;
    if (!myAid || this._closing || this._state !== 'connected') return;
    const started = Date.now();
    while (this._groupEpochRotationInflight.has(groupId)) {
      if (triggerId && this._groupMembershipRotationDone.has(triggerId)) return;
      if (this._closing || this._state !== 'connected') return;
      if (Date.now() - started > 20000) {
        this._clientLog.warn(`group epoch rotation still in-flight; skip pending trigger (group=${groupId} trigger=${triggerId || '-'})`);
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    if (this._closing || this._state !== 'connected') return;
    this._groupEpochRotationInflight.add(groupId);
    try {
      if (this._closing || this._state !== 'connected') return;
      const membersResp = await this.call('group.get_members', { group_id: groupId });
      if (!isJsonObject(membersResp)) return;
      const rawList = membersResp.members ?? membersResp.items;
      if (!Array.isArray(rawList)) return;
      const admins: string[] = [];
      const members: string[] = [];
      for (const m of rawList) {
        if (!isJsonObject(m)) continue;
        const role = String(m.role ?? '');
        const aid = String(m.aid ?? '');
        if (!aid) continue;
        if (role === 'admin' || role === 'owner') {
          admins.push(aid);
        } else if (allowMember && role === 'member') {
          members.push(aid);
        }
      }
      // 候选列表：admin/owner 排序在前，member 排序在后
      let candidates = [...admins.sort(), ...members.sort()];
      if (candidates.length === 0) return;

      // 没有当前 epoch key 的成员不参与 leader 选举。
      // open/invite_code 群排除后为空时保留自己兜底（从服务端取 prev chain）。
      if (expectedEpoch !== null && expectedEpoch > 0) {
        const localSecret = this._groupE2ee.loadSecret(groupId, expectedEpoch);
        if (!localSecret) {
          const filtered = candidates.filter(c => c !== myAid);
          if (filtered.length > 0) {
            candidates = filtered;
          } else if (!allowMember) {
            return;
          }
        }
      }

      const leader = candidates[0];
      if (leader === myAid) {
        // 我是 leader，直接发起
        await this._rotateGroupEpoch(groupId, triggerId, expectedEpoch);
        return;
      }
      if (!candidates.includes(myAid)) return;
      // 非 leader：随机 jitter（2~6s）后查询服务端 epoch 是否已被 leader 推进
      const jitterMs = 2000 + Math.floor(Math.random() * 4000);
      let beforeEpoch = 0;
      try {
        const resp = await this.call('group.e2ee.get_epoch', { group_id: groupId });
        if (isJsonObject(resp)) beforeEpoch = Number(resp.epoch ?? 0);
      } catch { beforeEpoch = (await this._groupE2ee.currentEpoch(groupId)) ?? 0; }
      await new Promise((r) => setTimeout(r, jitterMs));
      if (this._closing || this._state !== 'connected') return;
      let afterEpoch = 0;
      let afterResp: RpcResult = {};
      try {
        afterResp = await this.call('group.e2ee.get_epoch', { group_id: groupId });
        if (isJsonObject(afterResp)) afterEpoch = Number(afterResp.epoch ?? 0);
      } catch {
        afterEpoch = (await this._groupE2ee.currentEpoch(groupId)) ?? 0;
      }
      if (afterEpoch > beforeEpoch) return; // leader 已完成
      const pending = isJsonObject(afterResp) && isJsonObject(afterResp.pending_rotation) ? afterResp.pending_rotation : null;
      if (pending && !pending.expired) {
        this._scheduleGroupRotationRetry(groupId, {
          reason: 'membership_changed',
          triggerId,
          expectedEpoch,
          pending,
        });
        return;
      }
      this._clientLog.info(`[H21] leader 未完成 epoch 轮换，非 leader 兜底: group=${groupId} myAid=${myAid}`);
      await this._rotateGroupEpoch(groupId, triggerId, expectedEpoch);
    } catch (exc) {
      this._clientLog.warn(`_maybeLeadRotateGroupEpoch 失败: ${formatCaughtError(exc)}`);
    } finally {
      this._groupEpochRotationInflight.delete(groupId);
    }
  }

  /**
   * 群组解散后清理本地状态：
   * - keystore 中的 epoch key 数据
   * - seq_tracker 中的群消息和群事件 seq 记录
   * - 补洞去重缓存中的相关条目
   */
  private _cleanupDissolvedGroup(groupId: string): void {
    // 1. 清理 GroupE2EEManager / keystore 中的 epoch 密钥
    try {
      this._groupE2ee.removeGroup(groupId);
    } catch (exc) {
      this._clientLog.warn(`清理解散群组 ${groupId} epoch 密钥失败: ${formatCaughtError(exc)}`);
    }

    // 2. 清理 seq_tracker 中的群消息和群事件命名空间
    this._seqTracker.removeNamespace(`group:${groupId}`);
    this._seqTracker.removeNamespace(`group_event:${groupId}`);
    this._saveSeqTrackerState();

    // 3. 清理补洞去重缓存中的相关条目
    for (const key of this._gapFillDone.keys()) {
      if (key.includes(groupId)) {
        this._gapFillDone.delete(key);
      }
    }

    // 4. 清理推送 seq 去重缓存
    this._pushedSeqs.delete(`group:${groupId}`);
    this._pushedSeqs.delete(`group_event:${groupId}`);
    this._pendingOrderedMsgs.delete(`group:${groupId}`);
    this._pendingDecryptMsgs.delete(`group:${groupId}`);

    this._clientLog.info(`已清理解散群组 ${groupId} 的本地状态`);
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
          this._clientLog.warn(`验签失败：证书指纹不匹配 aid=${sigAid}`);
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
        this._clientLog.warn(`群事件验签失败 aid=${sigAid} method=${method}`);
        // P1-16: 签名失败统一发布事件
        this._dispatcher.publish('signature.verification_failed', {
          aid: sigAid, method, error: 'ECDSA verification failed',
        }).catch(() => {});
      }
      return ok;
    } catch (exc) {
      this._clientLog.warn(`群事件验签异常: ${formatCaughtError(exc)}`);
      // P1-16: 签名失败统一发布事件
      this._dispatcher.publish('signature.verification_failed', {
        aid: String(cs.aid ?? ''), method: String(cs._method ?? ''),
        error: formatCaughtError(exc),
      }).catch(() => {});
      return false;
    }
  }

  /** 尝试处理 P2P 传输的群组密钥消息。返回 true 表示已处理（不再传播）。 */
  private async _tryHandleGroupKeyMessage(message: Message): Promise<boolean> {
    const payload = message.payload;
    if (!isJsonObject(payload)) return false;

    const payloadObj = payload;

    // 控制面消息类型识别：只有明文 type 或 P2P 解密后内层 type 命中时才拦截。
    const GROUP_KEY_TYPES = new Set([
      'e2ee.group_key_distribution',
      'e2ee.group_key_request',
      'e2ee.group_key_response',
    ]);
    let isControlPlane = typeof payloadObj.type === 'string'
      && GROUP_KEY_TYPES.has(payloadObj.type as string);

    // 先解密 P2P E2EE（如果是加密的）
    // 注意：用 _decrypt_message 而非 decrypt_message，避免消耗 seen set
    let actualPayload: JsonObject | null = payloadObj;
    if (payloadObj.type === 'e2ee.encrypted') {
      const fromAid = String(message.from ?? '');
      const senderCertFingerprint = String(
        payloadObj.sender_cert_fingerprint ?? (payloadObj.aad as JsonObject | undefined)?.sender_cert_fingerprint ?? '',
      ).trim().toLowerCase();
      if (fromAid) {
        await this._ensureSenderCertCached(fromAid, senderCertFingerprint || undefined);
      }
      const decrypted = this._e2ee._decryptMessage(message);
      if (decrypted === null) return false;
      this._schedulePrekeyReplenishIfConsumed(decrypted);
      actualPayload = isJsonObject(decrypted.payload) ? decrypted.payload : null;
      if (actualPayload === null) return false;
      const innerType = actualPayload.type;
      if (typeof innerType === 'string' && GROUP_KEY_TYPES.has(innerType)) {
        isControlPlane = true;
      }
    }

    let result: string | null;
    if (actualPayload.type === 'e2ee.group_key_distribution') {
      if (!await this._verifyActiveGroupRotationDistribution(actualPayload)) {
        return true;
      }
    } else if (actualPayload.type === 'e2ee.group_key_response') {
      if (!await this._verifyGroupKeyResponseEpoch(actualPayload)) {
        return true;
      }
    }
    result = this._groupE2ee.handleIncoming(actualPayload);
    if (result === 'distribution') {
      await this._discardGroupDistributionIfStale(actualPayload);
      // 收到 epoch key 说明该群有活动，触发惰性同步建立 seq 基线
      const distGroupId = actualPayload.group_id as string;
      if (distGroupId && !this._groupSynced.has(distGroupId)) {
        this._lazySyncGroup(distGroupId).catch(() => {});
      }
    }
    // S14: 非控制面消息且 handleIncoming 不识别 → 不拦截
    if (!isControlPlane && result === null) return false;

    if (result === 'request') {
      // 处理密钥请求并回复
      const groupId = String(actualPayload.group_id ?? '');
      const requester = String(actualPayload.requester_aid ?? '');
      let members = this._groupE2ee.getMemberAids(groupId);

      // 请求者不在本地成员列表时，回源查询服务端最新成员列表，
      // 仅用于传递给 handleKeyRequestMsg 做鉴权，不更新本地密钥存储
      // （历史 epoch 的成员隔离由 handleKeyRequest 内部负责）。
      if (requester && !members.includes(requester)) {
        try {
          const membersResult = await this.call('group.get_members', { group_id: groupId });
          const memberList = isJsonObject(membersResult) && Array.isArray(membersResult.members)
            ? membersResult.members as MemberRecord[]
            : [];
          members = memberList.map(
            (m) => String(m.aid),
          );
        } catch (exc) {
          this._clientLog.warn(`群组 ${groupId} 成员列表回源失败: ${formatCaughtError(exc)}`);
        }
      }

      const response = this._groupE2ee.handleKeyRequestMsg(actualPayload, members);
      if (response && requester) {
        try {
          await this.call('message.send', {
            to: requester,
            payload: response,
            encrypt: true,
            persist_required: true,
          });
        } catch (exc) {
          this._clientLog.warn(`向 ${requester} 回复群组密钥失败: ${formatCaughtError(exc)}`);
        }
      }
    }

    // R4: 收到 distribution/response 后触发 pending 消息重试
    if (result === 'distribution' || result === 'response') {
      const groupId = String(actualPayload.group_id ?? '');
      const rotationId = String(actualPayload.rotation_id ?? '');
      const keyCommitment = String(actualPayload.commitment ?? '');
      if (rotationId && keyCommitment) {
        this._ackGroupRotationKey(rotationId, keyCommitment)
          .catch((exc) => this._clientLog.warn(`提交 epoch key ack 失败: ${formatCaughtError(exc)}`));
      }
      this._scheduleRetryPendingDecryptMsgs(groupId);
    }

    return true;
  }

  // ── E2EE 编排辅助 ─────────────────────────────────────────

  /**
   * 获取对方证书（带缓存 + 完整 PKI 验证）。
   * 跨域时自动路由到 peer 所在域的 Gateway。
   */
  private async _fetchPeerCert(aid: string, certFingerprint?: string): Promise<string> {
    const cacheKey = AUNClient._certCacheKey(aid, certFingerprint);
    const cached = this._certCache.get(cacheKey);
    const now = Date.now() / 1000;
    if (cached && now < cached.refreshAfter) {
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
      this._clientLog.error(`写入证书到 keystore 失败 (aid=${aid}, fp=${certFingerprint ?? ''}): ${formatCaughtError(exc)}`, exc instanceof Error ? exc : undefined);
    }

    return certPem;
  }

  /** 获取对方所有设备的 prekey 列表。 */
  private async _fetchPeerPrekeys(peerAid: string): Promise<PrekeyMaterial[]> {
    const cachedList = this._peerPrekeysCache.get(peerAid);
    if (cachedList && Date.now() / 1000 < cachedList.expireAt) {
      const normalized = normalizePeerPrekeys(cachedList.items);
      if (normalized.length > 0) {
        return normalized.map((item) => ({ ...item }));
      }
    }
    const cached = this._e2ee.getCachedPrekey(peerAid);
    if (cached !== null) {
      const normalized = normalizePeerPrekeys([cached]);
      if (normalized.length > 0) return normalized.map((item) => ({ ...item }));
    }

    try {
      const result = await this._transport.call('message.e2ee.get_prekey', { aid: peerAid });
      if (!isJsonObject(result)) {
        throw new ValidationError(`invalid prekey response for ${peerAid}`);
      }
      if (result.found === false) {
        return [];
      }

      const devicePrekeys = Array.isArray(result.device_prekeys) ? result.device_prekeys : null;
      if (devicePrekeys) {
        const normalized = normalizePeerPrekeys(devicePrekeys);
        if (normalized.length > 0) {
          this._peerPrekeysCache.set(peerAid, {
            items: normalized.map((item) => ({ ...item })),
            expireAt: Date.now() / 1000 + PEER_PREKEYS_CACHE_TTL,
          });
          this._e2ee.cachePrekey(peerAid, normalized[0]);
          return normalized;
        }
      }

      if (!isPeerPrekeyResponse(result)) {
        throw new ValidationError(`invalid prekey response for ${peerAid}`);
      }
      const prekey = result.prekey;
      if (prekey) {
        const normalized = normalizePeerPrekeys([prekey]);
        if (normalized.length > 0) {
          this._peerPrekeysCache.set(peerAid, {
            items: normalized.map((item) => ({ ...item })),
            expireAt: Date.now() / 1000 + PEER_PREKEYS_CACHE_TTL,
          });
          this._e2ee.cachePrekey(peerAid, normalized[0]);
          return normalized.map((item) => ({ ...item }));
        }
      }
      if (result.found) {
        throw new ValidationError(`invalid prekey response for ${peerAid}`);
      }
      return [];
    } catch (exc) {
      if (exc instanceof ValidationError) {
        throw exc;
      }
      throw new ValidationError(
        `failed to fetch peer prekey for ${peerAid}: ${exc instanceof Error ? exc.message : String(exc)}`,
      );
    }
  }

  /** 获取对方的单个 prekey（兼容接口，优先返回第一条 device prekey）。 */
  private async _fetchPeerPrekey(peerAid: string): Promise<PrekeyMaterial | null> {
    const cachedList = this._peerPrekeysCache.get(peerAid);
    if (cachedList && Date.now() / 1000 < cachedList.expireAt && cachedList.items.length > 0) {
      const normalized = normalizePeerPrekeys(cachedList.items);
      if (normalized.length > 0) {
        return { ...normalized[0] };
      }
    }
    const prekeys = await this._fetchPeerPrekeys(peerAid);
    if (prekeys.length === 0) {
      return null;
    }
    return { ...prekeys[0] };
  }

  /** 清除对端 prekey 的双层缓存（_peerPrekeysCache + e2ee 内部缓存） */
  private _invalidatePeerPrekeyCache(peerAid: string): void {
    this._peerPrekeysCache.delete(peerAid);
    this._e2ee.invalidatePrekeyCache(peerAid);
  }

  /** 清除对端证书缓存（精确匹配 aid 或 aid# 前缀的所有条目） */
  private _clearPeerCertCache(peerAid: string): void {
    for (const cacheKey of this._certCache.keys()) {
      if (cacheKey === peerAid || cacheKey.startsWith(`${peerAid}#`)) {
        this._certCache.delete(cacheKey);
      }
    }
  }

  /** 清除对端所有缓存后重新拉取 prekey（用于指纹不匹配时的强制刷新） */
  private async _refreshPeerPrekeys(peerAid: string): Promise<PrekeyMaterial[]> {
    this._invalidatePeerPrekeyCache(peerAid);
    this._clearPeerCertCache(peerAid);
    return await this._fetchPeerPrekeys(peerAid);
  }

  /** 生成 prekey 并上传到服务端 */
  private async _uploadPrekey(): Promise<UploadPrekeyResult> {
    const prekeyMaterial = this._e2ee.generatePrekey();
    const result = await this._transport.call('message.e2ee.put_prekey', prekeyMaterial);
    return isJsonObject(result) ? { ...result } : { ok: true };
  }

  /**
   * 确保发送方证书在本地 keystore 中可用且未过期。
   * 返回 true 表示证书已就绪（PKI 验证通过），false 表示不可用。
   */
  private async _ensureSenderCertCached(aid: string, certFingerprint?: string): Promise<boolean> {
    const cacheKey = AUNClient._certCacheKey(aid, certFingerprint);
    const cached = this._certCache.get(cacheKey);
    const now = Date.now() / 1000;
    if (cached && now < cached.refreshAfter) {
      return true;
    }
    const localCert = this._keystore.loadCert(aid, certFingerprint);
    if (localCert) {
      if (certFingerprint) {
        const actualFingerprint = `sha256:${new crypto.X509Certificate(localCert).fingerprint256.replace(/:/g, '').toLowerCase()}`;
        if (actualFingerprint !== String(certFingerprint).trim().toLowerCase()) {
          // 本地 active cert 与请求指纹不匹配，继续走远端获取
        } else {
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
      this._keystore.saveCert(aid, certPem, certFingerprint, { makeActive: false });
      return true;
    } catch (exc) {
      // 刷新失败时：若内存缓存有 PKI 验证过的证书（未过期 x2 倍 TTL）则继续用
      if (cached && now < cached.validatedAt + PEER_CERT_CACHE_TTL * 2) {
        this._clientLog.debug(`刷新发送方 ${aid} 证书失败，继续使用已验证的内存缓存: ${formatCaughtError(exc)}`);
        return true;
      }
      this._clientLog.warn(`获取发送方 ${aid} 证书失败且无已验证缓存，拒绝信任: ${formatCaughtError(exc)}`);
      return false;
    }
  }

  /**
   * 获取经过 PKI 验证的 peer 证书（仅信任内存缓存中已验证的证书）。
   * 零信任：不直接信任 keystore 中可能由恶意服务端注入的证书。
   */
  private _getVerifiedPeerCert(aid: string, certFingerprint?: string): string | null {
    let cached = this._certCache.get(AUNClient._certCacheKey(aid, certFingerprint));
    // 带 fingerprint 查不到时，降级用 aid 再查一次
    if (!cached && certFingerprint) {
      cached = this._certCache.get(AUNClient._certCacheKey(aid, undefined));
    }
    const now = Date.now() / 1000;
    if (cached && now < cached.validatedAt + PEER_CERT_CACHE_TTL * 2) {
      return cached.certPem;
    }
    return null;
  }

  /** 解密单条 P2P 消息 */
  private async _decryptSingleMessage(message: Message): Promise<Message> {
    const payload = message.payload;
    if (!isJsonObject(payload)) return message;
    const payloadObj = payload;
    if (payloadObj.type !== 'e2ee.encrypted') return message;
    if (message.encrypted === false) return message;

    // 确保发送方证书已缓存到 keystore
    const fromAid = String(message.from ?? '');
    const senderCertFingerprint = String(
      payloadObj.sender_cert_fingerprint ?? (payloadObj.aad as JsonObject | undefined)?.sender_cert_fingerprint ?? '',
    ).trim().toLowerCase();
    if (fromAid) {
      const certReady = await this._ensureSenderCertCached(fromAid, senderCertFingerprint || undefined);
      if (!certReady) {
        this._clientLog.warn(`无法获取发送方 ${fromAid} 的证书，跳过解密`);
        throw new Error(`发送方证书不可用: from=${fromAid}, mid=${message.message_id}`);
      }
    }

    // 密码学解密（E2EEManager.decryptMessage 内含本地防重放）
    const decrypted = this._e2ee.decryptMessage(message);
    this._schedulePrekeyReplenishIfConsumed(decrypted);
    // TS-015: 解密返回 null 表示失败（密文损坏/签名无效/重放等），
    // 不得回退到原始密文投递给应用层，应抛出错误触发 undecryptable 事件
    if (decrypted === null) {
      throw new Error(`E2EE 解密失败: from=${message.from}, mid=${message.message_id}`);
    }
    return decrypted;
  }

  /** 批量解密 P2P 消息（用于 message.pull） */
  private async _decryptMessages(messages: Message[]): Promise<Message[]> {
    const seenInBatch = new Set<string>();
    const result: Message[] = [];
    for (const msg of messages) {
      const mid = String(msg.message_id ?? '');
      if (mid && seenInBatch.has(mid)) continue;
      if (mid) seenInBatch.add(mid);

      const payload = msg.payload;
      if (isJsonObject(payload)
        && payload.type === 'e2ee.encrypted'
        && (msg.encrypted === true || !('encrypted' in msg))) {
        if (await this._tryHandleGroupKeyMessage(msg)) {
          continue;
        }
        const fromAid = String(msg.from ?? '');
        const senderCertFingerprint = String(
          payload.sender_cert_fingerprint ?? (payload.aad as JsonObject | undefined)?.sender_cert_fingerprint ?? '',
        ).trim().toLowerCase();
        if (fromAid) {
          const certReady = await this._ensureSenderCertCached(fromAid, senderCertFingerprint || undefined);
          if (!certReady) {
            this._clientLog.warn(`无法获取发送方 ${fromAid} 的证书，跳过解密`);
            continue;
          }
        }
        // pull 路径必须绕过本地 seen set，避免同一条消息先经 push 解密后再 pull 被误判为重放。
        const decrypted = this._e2ee._decryptMessage(msg);
        if (decrypted !== null) {
          result.push(decrypted);
        } else {
          // TS-015: 解密失败不回退到密文，跳过该消息并记录
          this._clientLog.warn(`pull 消息解密失败，跳过: from=${msg.from} mid=${msg.message_id}`);
        }
      } else {
        result.push(msg);
      }
    }
    return result;
  }

  /** 解密单条群组消息。opts.skipReplay 用于 group.pull 场景跳过防重放。 */
  private _enqueuePendingDecrypt(groupId: string, msg: Message): void {
    const ns = `group:${groupId}`;
    const queue = this._pendingDecryptMsgs.get(ns) ?? [];
    queue.push(msg as JsonObject);
    this._pendingDecryptMsgs.set(ns, queue.slice(-PENDING_DECRYPT_LIMIT));
  }

  private async _retryPendingDecryptMsgs(groupId: string): Promise<void> {
    const ns = `group:${groupId}`;
    const queue = this._pendingDecryptMsgs.get(ns);
    if (!queue || queue.length === 0) return;
    this._pendingDecryptMsgs.set(ns, []);
    const stillPending: JsonObject[] = [];
    for (const msg of queue) {
      try {
        const decrypted = await this._decryptGroupMessage(msg as Message);
        const payload = isJsonObject(msg.payload) ? msg.payload : null;
        if (payload?.type === 'e2ee.group_encrypted' && !decrypted.e2ee) {
          stillPending.push(msg);
          continue;
        }
        const seq = msg.seq;
        if (seq !== undefined && seq !== null) {
          await this._publishOrderedMessage('group.message_created', ns, seq, decrypted);
        } else {
          await this._publishAppEvent('group.message_created', decrypted);
        }
      } catch {
        stillPending.push(msg);
      }
    }
    const queuedDuringRetry = this._pendingDecryptMsgs.get(ns) ?? [];
    const mergedPending = [...stillPending, ...queuedDuringRetry].slice(-PENDING_DECRYPT_LIMIT);
    if (mergedPending.length) this._pendingDecryptMsgs.set(ns, mergedPending);
    else this._pendingDecryptMsgs.delete(ns);
  }

  private _scheduleRetryPendingDecryptMsgs(groupId: string): void {
    if (!groupId || !this._pendingDecryptMsgs.has(`group:${groupId}`)) return;
    this._retryPendingDecryptMsgs(groupId).catch((exc) =>
      this._clientLog.warn(`群 ${groupId} pending 消息重试失败: ${formatCaughtError(exc)}`),
    );
  }

  private async _recoverGroupEpochKey(groupId: string, epoch: number, senderAid = '', timeoutMs = 5000): Promise<boolean> {
    const existing = await this._groupE2ee.loadSecret(groupId, epoch);
    if (await this._groupEpochSecretReadyForRecovery(groupId, epoch, existing)) {
      this._scheduleRetryPendingDecryptMsgs(groupId);
      return true;
    }

    // inflight 去重：同 groupId:epoch 的并发恢复共享同一个 Promise
    const key = `${groupId}:${epoch}`;
    const inflight = this._groupEpochRecoveryInflight.get(key);
    if (inflight) return inflight;

    const promise = this._doRecoverGroupEpochKey(groupId, epoch, senderAid, timeoutMs)
      .finally(() => this._groupEpochRecoveryInflight.delete(key));
    this._groupEpochRecoveryInflight.set(key, promise);
    return promise;
  }

  private static _extractGroupJoinMode(payload: JsonValue | object | null | undefined): string {
    if (!isJsonObject(payload)) return '';
    for (const key of ['join_mode', 'mode']) {
      const v = String(payload[key] ?? '').trim().toLowerCase();
      if (v) return v;
    }
    for (const key of ['join_requirements', 'join']) {
      const nested = payload[key];
      if (isJsonObject(nested)) {
        for (const nk of ['mode', 'join_mode']) {
          const v = String(nested[nk] ?? '').trim().toLowerCase();
          if (v) return v;
        }
      }
    }
    if (isJsonObject(payload.group)) {
      const v = AUNClient._extractGroupJoinMode(payload.group);
      if (v) return v;
    }
    const settings = payload.settings;
    if (isJsonObject(settings)) {
      for (const key of ['join.mode', 'join_mode', 'mode']) {
        const v = String(settings[key] ?? '').trim().toLowerCase();
        if (v) return v;
      }
    }
    if (Array.isArray(settings)) {
      for (const item of settings) {
        if (!isJsonObject(item)) continue;
        const k = String(item.key ?? item.name ?? '').trim().toLowerCase();
        if (k === 'join.mode' || k === 'join_mode' || k === 'mode') {
          const v = String(item.value ?? '').trim().toLowerCase();
          if (v) return v;
        }
      }
    }
    return '';
  }

  private static _joinModeAllowsMemberEpochRotation(mode: string): boolean {
    const m = mode.trim().toLowerCase();
    return m === 'open' || m === 'invite_only' || m === 'invite_code';
  }

  private async _groupAllowsMemberEpochRotation(groupId: string): Promise<boolean> {
    try {
      const resp = await this.call('group.get_join_requirements', { group_id: groupId });
      const mode = AUNClient._extractGroupJoinMode(resp);
      if (mode) return AUNClient._joinModeAllowsMemberEpochRotation(mode);
    } catch { /* best effort */ }
    try {
      const resp = await this.call('group.get_settings', { group_id: groupId, keys: ['join.mode'] });
      const mode = AUNClient._extractGroupJoinMode(resp);
      if (mode) return AUNClient._joinModeAllowsMemberEpochRotation(mode);
    } catch { /* best effort */ }
    try {
      const resp = await this.call('group.get', { group_id: groupId });
      const mode = AUNClient._extractGroupJoinMode(resp);
      if (mode) return AUNClient._joinModeAllowsMemberEpochRotation(mode);
    } catch { /* best effort */ }
    return false;
  }

  /** 尝试从服务端拉取 ECIES 加密的 epoch key 并解密存入 keystore */
  private async _tryRecoverEpochKeyFromServer(groupId: string, epoch: number): Promise<boolean> {
    try {
      const params: JsonObject = { group_id: groupId };
      if (epoch > 0) params.epoch = epoch;
      const result = await this.call('group.e2ee.get_epoch_key', params);
      if (!isJsonObject(result)) return false;
      const encryptedB64 = result.encrypted_key;
      if (!encryptedB64 || typeof encryptedB64 !== 'string') return false;
      const serverEpoch = Number(result.epoch ?? epoch);

      const encryptedBytes = Buffer.from(encryptedB64, 'base64');
      // 用自己的 AID 私钥 ECIES 解密
      const myAid = this._aid || '';
      const keyPair = this._keystore.loadKeyPair(myAid);
      if (!keyPair?.private_key_pem) {
        this._clientLog.warn(`无法加载 AID 私钥用于 ECIES 解密: aid=${myAid}`);
        return false;
      }
      const { eciesDecrypt } = await import('./e2ee-group.js');
      const groupSecret = eciesDecrypt(keyPair.private_key_pem, encryptedBytes);
      if (!groupSecret || groupSecret.length !== 32) {
        this._clientLog.warn(`服务端 epoch key ECIES 解密结果长度异常: group=${groupId} epoch=${serverEpoch} len=${groupSecret?.length ?? 0}`);
        return false;
      }

      // 获取成员列表和 committed_rotation 用于 commitment / epoch_chain 验证
      let memberAids: string[] = [];
      let committedRotation: JsonObject | null = null;
      let epochChain = '';
      try {
        const epochInfo = await this.call('group.e2ee.get_epoch', { group_id: groupId });
        if (isJsonObject(epochInfo)) {
          if (Array.isArray(epochInfo.members)) {
            memberAids = epochInfo.members
              .map((m) => {
                if (typeof m === 'string') return m;
                if (isJsonObject(m) && typeof m.aid === 'string') return m.aid;
                return '';
              })
              .filter((s: string) => s.length > 0);
          }
          if (isJsonObject(epochInfo.committed_rotation)) {
            committedRotation = epochInfo.committed_rotation as JsonObject;
            const rawChain = String(committedRotation.epoch_chain ?? '').trim();
            if (rawChain) epochChain = rawChain;
            // 如果有 expected_members，用它覆盖 memberAids
            if (Array.isArray(committedRotation.expected_members) && committedRotation.expected_members.length > 0) {
              memberAids = (committedRotation.expected_members as unknown[])
                .map(item => String(item ?? '').trim())
                .filter(s => s.length > 0);
            }
          }
        }
      } catch { /* best effort */ }

      if (memberAids.length === 0) {
        this._clientLog.warn(`服务端 epoch key 恢复缺少成员快照: group=${groupId} epoch=${serverEpoch}`);
        return false;
      }

      const commitment = computeMembershipCommitment(memberAids, serverEpoch, groupId, groupSecret);

      // committed_rotation 存在时验证 commitment 和 epoch_chain
      let epochChainUnverified: boolean | null = null;
      let epochChainUnverifiedReason: string | null = null;
      if (committedRotation) {
        const committedEpoch = Number(committedRotation.target_epoch ?? serverEpoch);
        const committedCommitment = String(committedRotation.key_commitment ?? '').trim();
        if (committedEpoch === serverEpoch && committedCommitment && committedCommitment !== commitment) {
          this._clientLog.warn(`服务端 epoch key 恢复 commitment 不匹配: group=${groupId} epoch=${serverEpoch}`);
          return false;
        }
        if (epochChain && committedEpoch === serverEpoch) {
          let rotatorAid = '';
          for (const key of ['rotated_by', 'lease_owner', 'committed_by']) {
            const v = String(committedRotation[key] ?? '').trim();
            if (v) { rotatorAid = v; break; }
          }
          const prevData = this._groupE2ee.loadSecret(groupId, serverEpoch - 1);
          const prevChain = String(prevData?.epoch_chain ?? '').trim();
          if (prevChain && rotatorAid) {
            if (!verifyEpochChain(epochChain, prevChain, serverEpoch, commitment, rotatorAid)) {
              this._clientLog.warn(`服务端 epoch key 恢复 epoch_chain 验证失败: group=${groupId} epoch=${serverEpoch} rotator=${rotatorAid}`);
              return false;
            }
            epochChainUnverified = false;
          } else {
            epochChainUnverified = true;
            epochChainUnverifiedReason = prevChain ? 'missing_rotator_aid' : 'missing_prev_chain';
          }
        }
      }

      const stored = storeGroupSecretEpoch(this._keystore, myAid, groupId, serverEpoch, groupSecret, commitment, memberAids,
        epochChain || undefined, '', epochChainUnverified, epochChainUnverifiedReason);
      if (!stored) {
        this._clientLog.warn(`服务端 epoch key 恢复存储失败: group=${groupId} epoch=${serverEpoch}`);
        return false;
      }
      this._clientLog.info(`从服务端恢复 epoch key 成功: group=${groupId} epoch=${serverEpoch}`);
      return true;
    } catch (exc) {
      this._clientLog.debug(`从服务端恢复 epoch key 失败: group=${groupId} epoch=${epoch} err=${formatCaughtError(exc)}`);
      return false;
    }
  }

  /** 为每个成员用其 AID 证书公钥 ECIES 加密 group_secret，返回 {aid: base64_ciphertext} */
  private async _buildEpochEncryptedKeys(
    info: JsonObject,
    memberAids: string[],
    targetEpoch: number,
    groupId: string,
  ): Promise<JsonObject> {
    try {
      const { eciesEncrypt } = await import('./e2ee-group.js');
      // 从 distribution payload 中提取 group_secret
      let groupSecretBytes: Buffer | null = null;
      const distributions = Array.isArray(info.distributions) ? info.distributions : [];
      for (const dist of distributions) {
        if (isJsonObject(dist) && isJsonObject(dist.payload)) {
          const gsB64 = dist.payload.group_secret;
          if (typeof gsB64 === 'string' && gsB64.length > 0) {
            groupSecretBytes = Buffer.from(gsB64, 'base64');
            break;
          }
        }
      }
      if (!groupSecretBytes) {
        // fallback: 从本地 keystore 加载
        const loaded = this._groupE2ee.loadSecret(groupId, targetEpoch);
        if (loaded?.secret) {
          groupSecretBytes = loaded.secret;
        } else {
          this._clientLog.debug(`无法获取 group_secret 用于 ECIES 加密: group=${groupId} epoch=${targetEpoch}`);
          return {};
        }
      }

      const encryptedKeys: JsonObject = {};
      for (const aid of memberAids) {
        try {
          const certPem = await this._fetchPeerCert(aid);
          const x509Cert = new crypto.X509Certificate(certPem);
          const pubKey = x509Cert.publicKey;
          // 导出未压缩 EC 公钥点
          const jwk = pubKey.export({ format: 'jwk' });
          if (jwk.crv !== 'P-256' || !jwk.x || !jwk.y) continue;
          const xBuf = Buffer.from(jwk.x, 'base64url');
          const yBuf = Buffer.from(jwk.y, 'base64url');
          const pubkeyBytes = Buffer.concat([Buffer.from([0x04]), xBuf, yBuf]);
          const ciphertext = eciesEncrypt(pubkeyBytes, groupSecretBytes);
          encryptedKeys[aid] = ciphertext.toString('base64');
        } catch (exc) {
          this._clientLog.debug(`为成员 ${aid} 构建 ECIES epoch key 失败: ${formatCaughtError(exc)}`);
          continue;
        }
      }
      return encryptedKeys;
    } catch (exc) {
      this._clientLog.debug(`构建 encrypted_keys 失败: group=${groupId} err=${formatCaughtError(exc)}`);
      return {};
    }
  }

  private async _doRecoverGroupEpochKey(groupId: string, epoch: number, senderAid: string, timeoutMs: number): Promise<boolean> {
    // 仅 open / invite_code 群允许从服务端拉取 ECIES 加密的 epoch key
    if (await this._groupAllowsMemberEpochRotation(groupId)) {
      if (await this._tryRecoverEpochKeyFromServer(groupId, epoch)) {
        this._scheduleRetryPendingDecryptMsgs(groupId);
        return true;
      }
    }

    let epochResult: JsonObject = { epoch };
    try {
      const raw = await this.call('group.e2ee.get_epoch', { group_id: groupId });
      if (isJsonObject(raw)) epochResult = { ...epochResult, ...raw };
    } catch {
      // 候选查询失败时仍使用 sender/local members 兜底。
    }
    if (senderAid) {
      const current = Array.isArray(epochResult.recovery_candidates) ? epochResult.recovery_candidates : [];
      epochResult.recovery_candidates = [senderAid, ...current];
    }

    // 在线优先恢复：先查在线成员列表，只向在线成员发送密钥请求
    let onlineAids: string[] | null = null;
    try {
      const onlineResp = await this.call('group.get_online_members', { group_id: groupId });
      if (isJsonObject(onlineResp)) {
        const rawMembers = Array.isArray(onlineResp.members) ? onlineResp.members
          : Array.isArray(onlineResp.items) ? onlineResp.items : [];
        onlineAids = rawMembers
          .filter((m): m is JsonObject => isJsonObject(m) && m.online === true && String(m.aid ?? '') !== this._aid)
          .map(m => String(m.aid ?? ''));
      }
    } catch {
      this._clientLog.debug(`群 ${groupId} 查询在线成员失败，回退全量候选`);
    }

    if (onlineAids !== null) {
      if (onlineAids.length === 0) {
        this._clientLog.info(`群 ${groupId} epoch ${String(epoch)} 恢复失败：无在线成员可请求密钥`);
        return false;
      }
      await this._requestGroupKeyFromOnline(groupId, epoch, onlineAids, epochResult);
    } else {
      await this._requestGroupKeyFromCandidates(groupId, epoch, epochResult);
    }

    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 150));
      const secret = await this._groupE2ee.loadSecret(groupId, epoch);
      if (await this._groupEpochSecretReadyForRecovery(groupId, epoch, secret)) {
        this._scheduleRetryPendingDecryptMsgs(groupId);
        return true;
      }
    }
    const secret = await this._groupE2ee.loadSecret(groupId, epoch);
    const ready = await this._groupEpochSecretReadyForRecovery(groupId, epoch, secret);
    if (ready) this._scheduleRetryPendingDecryptMsgs(groupId);
    return ready;
  }

  /** 只向在线成员发送密钥恢复请求 */
  private async _requestGroupKeyFromOnline(groupId: string, epoch: number, onlineAids: string[], epochResult: JsonObject): Promise<void> {
    const candidates = this._groupKeyRecoveryCandidates(groupId, epochResult);
    const ordered: string[] = [];
    for (const aid of candidates) {
      if (onlineAids.includes(aid) && !ordered.includes(aid)) ordered.push(aid);
    }
    for (const aid of onlineAids) {
      if (!ordered.includes(aid)) ordered.push(aid);
    }
    for (const aid of ordered) {
      await this._requestGroupKeyFrom(groupId, aid, epoch);
    }
  }

  private async _groupEpochSecretReadyForRecovery(groupId: string, epoch: number, secret: any): Promise<boolean> {
    if (!isJsonObject(secret)) return false;
    const pendingRotationId = String(secret.pending_rotation_id ?? '').trim();
    if (!pendingRotationId) return true;
    return this._pendingGroupSecretStillCurrent(groupId, epoch, pendingRotationId);
  }

  private async _pendingGroupSecretStillCurrent(groupId: string, epoch: number, pendingRotationId: string): Promise<boolean> {
    try {
      const epochResult = await this.call('group.e2ee.get_epoch', { group_id: groupId });
      if (!isJsonObject(epochResult)) return false;
      const pending = isJsonObject(epochResult.pending_rotation) ? epochResult.pending_rotation : null;
      if (
        pending
        && !pending.expired
        && String(pending.rotation_id ?? '').trim() === pendingRotationId
      ) {
        return true;
      }
      const committedRotation = isJsonObject(epochResult.committed_rotation) ? epochResult.committed_rotation : null;
      const committedTargetEpoch = Number(committedRotation?.target_epoch ?? 0);
      return Boolean(
        committedRotation
        && Number.isFinite(committedTargetEpoch)
        && committedTargetEpoch === epoch
        && String(committedRotation.rotation_id ?? '').trim() === pendingRotationId,
      );
    } catch {
      return false;
    }
  }

  private async _decryptGroupMessage(
    message: Message,
    opts?: { skipReplay?: boolean },
  ): Promise<Message> {
    const payload = message.payload;
    if (!isJsonObject(payload)) return this._attachGroupDispatchModeToPayload(message);
    const payloadObj = payload;
    if (payloadObj.type !== 'e2ee.group_encrypted') return this._attachGroupDispatchModeToPayload(message);

    // 确保发送方证书已缓存（签名验证需要）
    const senderAid = String(message.from ?? message.sender_aid ?? '');
    if (senderAid) {
      const certOk = await this._ensureSenderCertCached(senderAid);
      if (!certOk) {
        this._clientLog.warn(`群消息解密跳过：发送方 ${senderAid} 证书不可用`);
        return message;
      }
    }

    // 先尝试直接解密
    const result = this._groupE2ee.decrypt(message, opts);
    if (result !== null && result.e2ee) {
      return this._attachGroupDispatchModeToPayload(result);
    }

    // replay guard 命中：decrypt 返回了原消息（非 null）但无 e2ee 字段
    // 不是解密失败，不应触发 recover
    if (result !== null) {
      return result;
    }

    // 真正的解密失败（result === null），尝试密钥恢复后重试
    const groupId = String(message.group_id ?? '');
    const sender = String(message.from ?? message.sender_aid ?? '');
    const epoch = Number(payloadObj.epoch ?? 0);
    if (epoch > 0 && groupId) {
      try {
        if (await this._recoverGroupEpochKey(groupId, epoch, sender, 5000)) {
          const retry = await this._groupE2ee.decrypt(message, opts);
          if (retry !== null && retry.e2ee) return this._attachGroupDispatchModeToPayload(retry);
        }
      } catch (exc) {
        this._clientLog.debug(`群 ${groupId} epoch ${epoch} 同步恢复失败: ${formatCaughtError(exc)}`);
      }
    }

    return message;
  }

  private _attachGroupDispatchModeToPayload(message: Message): Message {
    const payload = message.payload;
    if (!isJsonObject(payload)) return message;
    const rawMode = String(message.dispatch_mode ?? 'broadcast').trim().toLowerCase();
    const mode = rawMode === 'mention' || rawMode === 'broadcast' ? rawMode : 'broadcast';
    return {
      ...message,
      dispatch_mode: mode,
      payload: {
        ...payload,
        dispatch_mode: mode,
      },
    };
  }

  /** 批量解密群组消息（用于 group.pull，跳过防重放） */
  private async _decryptGroupMessages(messages: Message[]): Promise<Message[]> {
    const result: Message[] = [];
    for (const msg of messages) {
      const decrypted = await this._decryptGroupMessage(msg);
      const payload = isJsonObject(msg.payload) ? msg.payload : null;
      const groupId = String(msg.group_id ?? '');
      if (payload?.type === 'e2ee.group_encrypted' && groupId && !decrypted.e2ee) {
        this._enqueuePendingDecrypt(groupId, msg);
        continue; // R3: 解密失败不入 result，不 publish 密文给应用层
      }
      if (payload?.type !== 'e2ee.group_encrypted') {
        result.push(this._attachGroupDispatchModeToPayload(decrypted));
        continue;
      }
      result.push(decrypted);
    }
    return result;
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
      const message: Message = {
        group_id: groupId,
        sender_aid: senderAid,
        from: senderAid,
        message_id: thoughtId,
        payload: payload ?? {},
        created_at: Number(item.created_at ?? 0),
      } as Message;
      if (isJsonObject(item.context)) message.context = item.context;
      const decrypted = await this._decryptGroupMessage(message, { skipReplay: true });
      let decryptFailed = false;
      if (payload?.type === 'e2ee.group_encrypted' && groupId && !decrypted.e2ee) {
        decryptFailed = true;
        // 安全网：触发 epoch key 恢复（内部有去重，重复调用安全）
        const epoch = Number((payload as JsonObject).epoch ?? 0);
        if (epoch > 0) {
          this._recoverGroupEpochKey(groupId, epoch, senderAid, 5000).catch(() => {});
        }
      }
      const thought: JsonObject = {
        thought_id: thoughtId,
        message_id: thoughtId,
        payload: decryptFailed ? (payload ?? {}) : decrypted.payload,
        created_at: item.created_at,
        e2ee: decrypted.e2ee,
      };
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
      const message: Message = {
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
      if (payload?.type === 'e2ee.encrypted') {
        const senderCertFingerprint = String(
          payload.sender_cert_fingerprint ?? (payload.aad as JsonObject | undefined)?.sender_cert_fingerprint ?? '',
        ).trim().toLowerCase();
        if (fromAid) {
          const certReady = await this._ensureSenderCertCached(fromAid, senderCertFingerprint || undefined);
          if (!certReady) {
            this._clientLog.warn(`无法获取发送方 ${fromAid} 的证书，跳过 message.thought.get 解密`);
            decryptFailed = true;
          }
        }
        if (!decryptFailed) {
          decrypted = this._e2ee._decryptMessage(message);
          if (decrypted === null || (isJsonObject(decrypted.payload) && decrypted.payload.type === 'e2ee.encrypted')) {
            decryptFailed = true;
            decrypted = message;
          }
        }
      }
      const thought: JsonObject = {
        thought_id: thoughtId,
        message_id: thoughtId,
        from: fromAid,
        to: toAid,
        payload: decryptFailed ? (payload ?? {}) : (decrypted!.payload as JsonObject),
        created_at: item.created_at,
        e2ee: decryptFailed ? undefined : (decrypted!.e2ee as JsonValue),
      };
      if (decryptFailed) thought.decrypt_failed = true;
      if ('context' in item) thought.context = item.context;
      thoughts.push(thought);
    }
    return { ...result, thoughts };
  }

  // ── Group E2EE 编排 ───────────────────────────────────────

  private _attachRotationId(info: JsonObject, rotationId: string): void {
    if (!rotationId || !Array.isArray(info.distributions)) return;
    for (const dist of info.distributions) {
      if (isJsonObject(dist) && isJsonObject(dist.payload)) {
        dist.payload.rotation_id = rotationId;
      }
    }
  }

  private async _getGroupMemberAids(groupId: string): Promise<string[]> {
    const membersResult = await this.call('group.get_members', { group_id: groupId });
    const rawList = isJsonObject(membersResult)
      ? (Array.isArray(membersResult.members) ? membersResult.members : membersResult.items)
      : [];
    if (!Array.isArray(rawList)) return [];
    const aids: string[] = [];
    for (const item of rawList) {
      if (!isJsonObject(item)) continue;
      const aid = String(item.aid ?? '').trim();
      if (aid) aids.push(aid);
    }
    return aids;
  }

  private async _distributeGroupEpochKey(info: JsonObject, rotationId = ''): Promise<{ sent: string[]; failed: string[] }> {
    const sent: string[] = [];
    const failed: string[] = [];
    let lastHeartbeat = Date.now();
    const distributions = (Array.isArray(info.distributions) ? info.distributions : []) as GroupDistribution[];
    for (const dist of distributions) {
      if (!isJsonObject(dist) || !dist.to || !isJsonObject(dist.payload)) continue;
      if (rotationId && Date.now() - lastHeartbeat >= 20_000) {
        if (await this._heartbeatGroupRotation(rotationId)) lastHeartbeat = Date.now();
      }
      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          await this.call('message.send', {
            to: dist.to,
            payload: dist.payload,
            encrypt: true,
            persist_required: true,
          });
          sent.push(String(dist.to));
          break;
        } catch (exc) {
          if (attempt < 2) {
            await new Promise(resolve => setTimeout(resolve, (attempt + 1) * 1000));
          } else {
            failed.push(String(dist.to));
            this._clientLog.warn(`epoch 密钥分发失败 (to=${dist.to}): ${formatCaughtError(exc)}`);
          }
        }
      }
    }
    return { sent, failed };
  }

  private async _heartbeatGroupRotation(rotationId: string): Promise<boolean> {
    if (!rotationId) return false;
    try {
      const result = await this.call('group.e2ee.heartbeat_rotation', {
        rotation_id: rotationId,
        lease_ms: GROUP_ROTATION_LEASE_MS,
      });
      return isJsonObject(result) && result.success === true;
    } catch (exc) {
      this._clientLog.warn(`刷新 epoch rotation lease 失败: rotation=${rotationId} err=${formatCaughtError(exc)}`);
      return false;
    }
  }

  private async _ackGroupRotationKey(rotationId: string, keyCommitment: string, deviceId?: string): Promise<boolean> {
    if (!rotationId) return false;
    try {
      const result = await this.call('group.e2ee.ack_rotation_key', {
        rotation_id: rotationId,
        key_commitment: keyCommitment,
        device_id: deviceId ?? this._deviceId,
      });
      return isJsonObject(result) && result.success === true;
    } catch (exc) {
      this._clientLog.warn(`提交 epoch key ack 失败: rotation=${rotationId} err=${formatCaughtError(exc)}`);
      return false;
    }
  }

  private async _verifyActiveGroupRotationDistribution(payload: JsonObject): Promise<boolean> {
    const rotationId = String(payload.rotation_id ?? '').trim();
    const groupId = String(payload.group_id ?? '').trim();
    if (!groupId) return false;
    const epoch = Number(payload.epoch ?? 0);
    if (!Number.isFinite(epoch) || epoch <= 0) return false;
    const commitment = String(payload.commitment ?? '').trim();
    try {
      const epochResult = await this.call('group.e2ee.get_epoch', { group_id: groupId });
      if (!isJsonObject(epochResult)) return false;
      const committedRotation = isJsonObject(epochResult.committed_rotation) ? epochResult.committed_rotation : null;
      const committedEpoch = Number(epochResult.committed_epoch ?? epochResult.epoch ?? 0);
      if (!rotationId) {
        if (Number.isFinite(epoch) && epoch > 0 && epoch <= committedEpoch) {
          if (committedRotation && Number(committedRotation.target_epoch ?? committedEpoch) === epoch) {
            const committedCommitment = String(committedRotation.key_commitment ?? '').trim();
            if (committedCommitment && commitment && committedCommitment !== commitment) {
              const expectedMembers = Array.isArray(committedRotation.expected_members)
                ? committedRotation.expected_members.map((item) => String(item ?? '').trim()).filter(Boolean)
                : [];
              if (this._aid && !expectedMembers.includes(this._aid)) {
                this._clientLog.debug(`放行 group key 分发：新成员恢复 commitment 不匹配属正常 group=${groupId} epoch=${epoch}`);
              } else {
                return false;
              }
            }
          }
          return true;
        }
        this._clientLog.info(`拒绝缺少 rotation_id 的未来 epoch key 分发: group=${groupId} epoch=${epoch} committed=${committedEpoch}`);
        return false;
      }
      const pending = isJsonObject(epochResult.pending_rotation) ? epochResult.pending_rotation : null;
      if (pending && !pending.expired) {
        const pendingCommitment = String(pending.key_commitment ?? '').trim();
        if (
          String(pending.rotation_id ?? '') === rotationId
          && Number(pending.target_epoch ?? 0) === epoch
          && (!pendingCommitment || pendingCommitment === commitment)
        ) {
          return true;
        }
      }
      if (committedRotation && committedEpoch >= epoch) {
        const committedCommitment = String(committedRotation.key_commitment ?? '').trim();
        if (
          String(committedRotation.rotation_id ?? '') === rotationId
          && (!committedCommitment || committedCommitment === commitment)
        ) {
          return true;
        }
      }
    } catch (exc) {
      this._clientLog.warn(`拒绝无法校验 active rotation 的 epoch key 分发: group=${groupId} rotation=${rotationId} err=${formatCaughtError(exc)}`);
      return false;
    }
    this._clientLog.info(`拒绝非 pending/committed 状态的 epoch key 分发: group=${groupId} rotation=${rotationId} epoch=${epoch}`);
    return false;
  }

  private async _discardGroupDistributionIfStale(payload: JsonObject): Promise<void> {
    const rotationId = String(payload.rotation_id ?? '').trim();
    if (!rotationId) return;
    const groupId = String(payload.group_id ?? '').trim();
    const epoch = Number(payload.epoch ?? 0);
    if (!groupId || !Number.isFinite(epoch) || epoch <= 0) return;
    if (await this._verifyActiveGroupRotationDistribution(payload)) return;
    try {
      this._groupE2ee.discardPendingSecret(groupId, epoch, rotationId);
      this._clientLog.info(`丢弃 verify 后变为 stale 的 group epoch key: group=${groupId} epoch=${epoch} rotation=${rotationId}`);
    } catch (exc) {
      this._clientLog.debug(`清理 stale group epoch key 失败: group=${groupId} epoch=${epoch} rotation=${rotationId} err=${formatCaughtError(exc)}`);
    }
  }

  private async _verifyGroupKeyResponseEpoch(payload: JsonObject): Promise<boolean> {
    const groupId = String(payload.group_id ?? '').trim();
    if (!groupId) return false;
    const epoch = Number(payload.epoch ?? 0);
    if (!Number.isFinite(epoch) || epoch <= 0) return false;
    const commitment = String(payload.commitment ?? '').trim();
    try {
      const epochResult = await this.call('group.e2ee.get_epoch', { group_id: groupId });
      if (!isJsonObject(epochResult)) return false;
      const committedEpoch = Number(epochResult.committed_epoch ?? epochResult.epoch ?? 0);
      if (epoch > committedEpoch) {
        this._clientLog.info(`拒绝未提交 epoch 的 group key response: group=${groupId} epoch=${epoch} committed=${committedEpoch}`);
        return false;
      }
      const committedRotation = isJsonObject(epochResult.committed_rotation) ? epochResult.committed_rotation : null;
      if (committedRotation && Number(committedRotation.target_epoch ?? committedEpoch) === epoch) {
        const committedCommitment = String(committedRotation.key_commitment ?? '').trim();
        if (committedCommitment && commitment && committedCommitment !== commitment) {
          const expectedMembers = Array.isArray(committedRotation.expected_members)
            ? committedRotation.expected_members.map((item) => String(item ?? '').trim()).filter(Boolean)
            : [];
          if (this._aid && !expectedMembers.includes(this._aid)) {
            this._clientLog.debug(`放行 group key response：新成员恢复 commitment 不匹配属正常 group=${groupId} epoch=${epoch}`);
          } else {
            return false;
          }
        }
      }
      return true;
    } catch (exc) {
      this._clientLog.warn(`拒绝无法校验 committed epoch 的 group key response: group=${groupId} epoch=${epoch} err=${formatCaughtError(exc)}`);
      return false;
    }
  }

  private async _abortGroupRotation(rotationId: string, reason = ''): Promise<boolean> {
    if (!rotationId) return false;
    try {
      const result = await this.call('group.e2ee.abort_rotation', {
        rotation_id: rotationId,
        reason: reason || 'client_abort',
      });
      return isJsonObject(result) && result.success === true;
    } catch (exc) {
      this._clientLog.warn(`中止 epoch rotation 失败: rotation=${rotationId} err=${formatCaughtError(exc)}`);
      return false;
    }
  }

  private _rotationExpectedMembersStale(rotation: JsonObject, memberAids: string[]): boolean {
    const expected = Array.isArray(rotation.expected_members)
      ? rotation.expected_members.map((item) => String(item ?? '').trim()).filter(Boolean).sort()
      : [];
    const current = memberAids.map((item) => String(item ?? '').trim()).filter(Boolean).sort();
    return expected.length > 0 && current.length > 0 && expected.join('\n') !== current.join('\n');
  }

  private _rotationRetryDelayMs(pending: JsonObject | null): number {
    let leaseExpiresAt = 0;
    if (pending && !pending.expired && ['', 'distributing'].includes(String(pending.status ?? ''))) {
      const parsed = Number(pending.lease_expires_at ?? 0);
      if (Number.isFinite(parsed)) leaseExpiresAt = parsed;
    }
    const base = leaseExpiresAt
      ? Math.max(1000, leaseExpiresAt - Date.now() + 1000)
      : 5000;
    return Math.min(base + Math.floor(Math.random() * 2000), GROUP_ROTATION_RETRY_MAX_DELAY_MS);
  }

  private _scheduleGroupRotationRetry(
    groupId: string,
    opts: { reason: string; triggerId: string; expectedEpoch: number | null; pending: JsonObject | null },
  ): void {
    if (this._closing || this._state !== 'connected') return;
    const retryKey = `${groupId}:${opts.triggerId || opts.reason}:${opts.expectedEpoch ?? '-'}`;
    if (this._groupEpochRotationRetryTimers.has(retryKey)) return;
    const timer = setTimeout(() => {
      this._groupEpochRotationRetryTimers.delete(retryKey);
      if (this._closing || this._state !== 'connected') return;
      this._maybeLeadRotateGroupEpoch(groupId, opts.triggerId, opts.expectedEpoch)
        .catch((exc) => this._clientLog.warn(`group epoch rotation retry failed: ${formatCaughtError(exc)}`));
    }, this._rotationRetryDelayMs(opts.pending));
    this._groupEpochRotationRetryTimers.set(retryKey, timer);
    this._unrefTimer(timer);
  }

  /** 建群后将本地 epoch 1 同步到服务端（服务端初始为 0），最多重试 3 次 */
  private async _syncEpochToServer(groupId: string): Promise<void> {
    const started = Date.now();
    while (this._groupEpochRotationInflight.has(groupId)) {
      if (this._closing || this._state !== 'connected') return;
      if (Date.now() - started > 20000) {
        this._clientLog.warn(`group epoch create sync still in-flight; skip duplicate sync (group=${groupId})`);
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    if (this._closing || this._state !== 'connected') return;
    this._groupEpochRotationInflight.add(groupId);
    try {
      const maxRetries = 3;
      for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
          if (!this._aid) return;
          const secretData = this._groupE2ee.loadSecret(groupId, 1);
          if (!secretData) throw new StateError(`group ${groupId} epoch 1 secret missing`);
          const rotationId = `rot-${crypto.randomUUID().replace(/-/g, '')}`;
          const rotateParams: RpcParams = {
            group_id: groupId,
            base_epoch: 0,
            target_epoch: 1,
            rotation_id: rotationId,
            reason: 'create_group',
            key_commitment: secretData.commitment,
            expected_members: secretData.member_aids.length > 0 ? secretData.member_aids : [this._aid],
            required_acks: [this._aid],
            lease_ms: GROUP_ROTATION_LEASE_MS,
          };
          Object.assign(rotateParams, this._buildRotationSignature(groupId, 0, 1, rotateParams));
          const beginResult = await this.call('group.e2ee.begin_rotation', rotateParams);
          const rotation = isJsonObject(beginResult) && isJsonObject(beginResult.rotation) ? beginResult.rotation : null;
          if (!isJsonObject(beginResult) || beginResult.success !== true || !rotation) {
            this._clientLog.warn(`group epoch begin failed; stop key distribution (group=${groupId}, returned=${JSON.stringify(beginResult)})`);
            return;
          }
          const activeRotationId = String(rotation.rotation_id ?? rotationId);
          if (!await this._ackGroupRotationKey(activeRotationId, secretData.commitment)) {
            this._clientLog.warn(`group epoch self ack failed (group=${groupId}, rotation=${activeRotationId})`);
            await this._abortGroupRotation(activeRotationId, 'self_ack_failed');
            return;
          }
          const commitParams2: JsonObject = { rotation_id: activeRotationId };
          const createMembers = secretData.member_aids.length > 0 ? secretData.member_aids : (this._aid ? [this._aid] : []);
          const encKeys2 = await this._buildEpochEncryptedKeys(
            { distributions: [{ payload: { group_secret: secretData.secret.toString('base64') } }] } as any,
            createMembers, 1, groupId,
          );
          if (await this._groupAllowsMemberEpochRotation(groupId)) {
            if (encKeys2 && Object.keys(encKeys2).length > 0) {
              commitParams2.encrypted_keys = encKeys2;
            }
          }
          const commitResult = await this.call('group.e2ee.commit_rotation', commitParams2);
          if (isJsonObject(commitResult) && commitResult.success === true) {
            storeGroupSecret(
              this._keystore,
              this._aid,
              groupId,
              1,
              secretData.secret,
              secretData.commitment,
              secretData.member_aids,
              secretData.epoch_chain,
            );
            return;
          }
          this._clientLog.warn(`group epoch commit failed (group=${groupId}, returned=${JSON.stringify(commitResult)})`);
          return;
        } catch (exc) {
          if (attempt < maxRetries) {
            const delay = 500 * Math.pow(2, attempt - 1);
            this._clientLog.warn(`同步 epoch 到服务端失败 (group=${groupId}, 第${attempt}/${maxRetries}次): ${formatCaughtError(exc)}, ${delay}ms后重试`);
            await new Promise(r => setTimeout(r, delay));
          } else {
            this._clientLog.error(`同步 epoch 到服务端最终失败 (group=${groupId}, 已重试${maxRetries}次): ${formatCaughtError(exc)}`, exc instanceof Error ? exc : undefined);
          }
        }
      }
    } finally {
      this._groupEpochRotationInflight.delete(groupId);
    }
  }

  /**
   * 为指定群组轮换 epoch 并分发新密钥。
   * 使用服务端两阶段 rotation，避免服务端先提交但密钥未分发。
   */
  private async _rotateGroupEpoch(groupId: string, triggerId = '', expectedEpoch: number | null = null): Promise<void> {
    try {
      if (!this._aid) return;
      const memberAids = await this._getGroupMemberAids(groupId);
      if (triggerId && this._groupMembershipRotationDone.has(triggerId)) return;

      const epochResult = await this.call('group.e2ee.get_epoch', { group_id: groupId });
      const serverEpoch = isJsonObject(epochResult) ? Number(epochResult.epoch ?? 0) : 0;
      const pendingRotation = isJsonObject(epochResult) && isJsonObject(epochResult.pending_rotation)
        ? epochResult.pending_rotation
        : null;
      if (pendingRotation && !pendingRotation.expired) {
        const pendingRotationId = String(pendingRotation.rotation_id ?? '');
        const stalePending = (
          expectedEpoch !== null
          && serverEpoch === expectedEpoch
          && this._rotationExpectedMembersStale(pendingRotation, memberAids)
        );
        if (stalePending && await this._abortGroupRotation(pendingRotationId, 'membership_changed_during_rotation')) {
          this._clientLog.info(`aborted stale pending group epoch rotation: group=${groupId} rotation=${pendingRotationId || '-'}`);
        } else {
          this._scheduleGroupRotationRetry(groupId, {
            reason: 'membership_changed',
            triggerId,
            expectedEpoch,
            pending: pendingRotation,
          });
          return;
        }
      }
      if (expectedEpoch !== null && serverEpoch !== expectedEpoch) {
        if (triggerId) this._groupMembershipRotationDone.add(triggerId);
        this._clientLog.info(`skip membership epoch rotation: group=${groupId} expected_epoch=${expectedEpoch} server_epoch=${serverEpoch} trigger=${triggerId || '-'}`);
        return;
      }
      const currentEpoch = expectedEpoch ?? serverEpoch;
      const targetEpoch = currentEpoch + 1;
      // 新成员可能没有 prev epoch key，或有 key 但缺少 epoch_chain（通过 backfill 接收）。
      // 从 committed_rotation.epoch_chain 获取 prev chain hint。
      let prevChainHint: string | null = null;
      const localPrev = this._groupE2ee.loadSecret(groupId, currentEpoch);
      const localPrevChain = String((localPrev as any)?.epoch_chain ?? '');
      if (!localPrevChain && isJsonObject(epochResult)) {
        const cr = epochResult.committed_rotation;
        if (isJsonObject(cr)) {
          const rawChain = String(cr.epoch_chain ?? '').trim();
          if (rawChain) {
            prevChainHint = rawChain;
            this._clientLog.info(`新成员轮换补充 prev epoch chain from server: group=${groupId} epoch=${currentEpoch}`);
          }
        }
      }
      const rotationId = `rot-${crypto.randomUUID().replace(/-/g, '')}`;
      const info = this._groupE2ee.rotateEpochTo(groupId, targetEpoch, memberAids, { rotationId, prevChainHint });
      this._attachRotationId(info, rotationId);
      const discardGeneratedPending = (): void => {
        try {
          this._groupE2ee.discardPendingSecret(groupId, targetEpoch, rotationId);
        } catch (cleanupExc) {
          this._clientLog.debug(`清理本地 pending group key 失败: group=${groupId} epoch=${targetEpoch} rotation=${rotationId} err=${formatCaughtError(cleanupExc)}`);
        }
      };

      const rotateParams: RpcParams = {
        group_id: groupId,
        base_epoch: currentEpoch,
        target_epoch: targetEpoch,
        rotation_id: rotationId,
        reason: triggerId || expectedEpoch !== null ? 'membership_changed' : 'manual',
        key_commitment: String(info.commitment ?? ''),
        expected_members: memberAids,
        required_acks: [this._aid],
        lease_ms: GROUP_ROTATION_LEASE_MS,
      };
      Object.assign(rotateParams, this._buildRotationSignature(groupId, currentEpoch, targetEpoch, rotateParams));
      let rawBeginResult: any;
      try {
        rawBeginResult = await this.call('group.e2ee.begin_rotation', rotateParams);
      } catch (exc) {
        discardGeneratedPending();
        throw exc;
      }
      const beginResult = isJsonObject(rawBeginResult) ? rawBeginResult : null;
      const beginRotationRaw = beginResult ? beginResult.rotation : null;
      const rotation = isJsonObject(beginRotationRaw) ? beginRotationRaw : null;
      if (!beginResult || beginResult.success !== true || !rotation) {
        if (rotation && !rotation.expired) {
          if (
            this._rotationExpectedMembersStale(rotation, memberAids)
            && await this._abortGroupRotation(String(rotation.rotation_id ?? ''), 'membership_changed_during_rotation')
          ) {
            this._scheduleGroupRotationRetry(groupId, {
              reason: 'membership_changed',
              triggerId,
              expectedEpoch,
              pending: null,
            });
          } else {
            this._scheduleGroupRotationRetry(groupId, {
              reason: 'membership_changed',
              triggerId,
              expectedEpoch,
              pending: rotation,
            });
          }
        } else if (beginResult && beginResult.reason === 'expected_members_mismatch') {
          this._scheduleGroupRotationRetry(groupId, {
            reason: 'membership_changed',
            triggerId,
            expectedEpoch,
            pending: null,
          });
        }
        this._clientLog.warn(`group epoch begin failed; stop key distribution (group=${groupId}, current_epoch=${currentEpoch}, returned=${JSON.stringify(beginResult)})`);
        discardGeneratedPending();
        return;
      }

      const activeRotationId = String(rotation.rotation_id ?? rotationId);
      const distributeResult = await this._distributeGroupEpochKey(info, activeRotationId);
      if (distributeResult.failed.length > 0) {
        this._clientLog.warn(`group epoch key distribution incomplete; abort rotation before retry (group=${groupId} rotation=${activeRotationId} failed=${distributeResult.failed.join(',')})`);
        await this._abortGroupRotation(activeRotationId, 'distribution_failed');
        this._scheduleGroupRotationRetry(groupId, {
          reason: 'membership_changed',
          triggerId,
          expectedEpoch,
          pending: null,
        });
        discardGeneratedPending();
        return;
      }
      await this._heartbeatGroupRotation(activeRotationId);
      if (!await this._ackGroupRotationKey(activeRotationId, String(info.commitment ?? ''))) {
        this._clientLog.warn(`group epoch self ack failed; abort rotation before retry (group=${groupId} rotation=${activeRotationId})`);
        await this._abortGroupRotation(activeRotationId, 'self_ack_failed');
        this._scheduleGroupRotationRetry(groupId, {
          reason: 'membership_changed',
          triggerId,
          expectedEpoch,
          pending: null,
        });
        discardGeneratedPending();
        return;
      }
      const commitParams: JsonObject = { rotation_id: activeRotationId };
      // 构建 per-member ECIES 加密的 epoch key 上传到服务端
      if (await this._groupAllowsMemberEpochRotation(groupId)) {
        const encryptedKeys = await this._buildEpochEncryptedKeys(info, memberAids, targetEpoch, groupId);
        if (encryptedKeys && Object.keys(encryptedKeys).length > 0) {
          commitParams.encrypted_keys = encryptedKeys;
        }
      }
      const commitResult = await this.call('group.e2ee.commit_rotation', commitParams);
      if (!isJsonObject(commitResult) || commitResult.success !== true) {
        this._clientLog.warn(`group epoch commit failed (group=${groupId}, rotation=${activeRotationId}, returned=${JSON.stringify(commitResult)})`);
        this._scheduleGroupRotationRetry(groupId, {
          reason: 'membership_changed',
          triggerId,
          expectedEpoch,
          pending: isJsonObject(commitResult) && isJsonObject(commitResult.rotation) ? commitResult.rotation : rotation,
        });
        const returnedRotation = isJsonObject(commitResult) && isJsonObject(commitResult.rotation) ? commitResult.rotation : null;
        if (!(returnedRotation
          && String(returnedRotation.rotation_id ?? '') === activeRotationId
          && String(returnedRotation.status ?? '') === 'distributing')) {
          discardGeneratedPending();
        }
        return;
      }
      const committedSecret = this._groupE2ee.loadSecret(groupId, targetEpoch);
      if (committedSecret && this._aid) {
        const committedRotation = isJsonObject(commitResult.rotation)
          ? commitResult.rotation
          : { rotation_id: activeRotationId, key_commitment: String(info.commitment ?? '') };
        if (this._groupSecretMatchesCommittedRotation(committedSecret as unknown as JsonObject, committedRotation)) {
          storeGroupSecret(
            this._keystore,
            this._aid,
            groupId,
            targetEpoch,
            committedSecret.secret,
            committedSecret.commitment,
            committedSecret.member_aids.length > 0 ? committedSecret.member_aids : memberAids,
            committedSecret.epoch_chain,
          );
        } else {
          this._clientLog.warn(`group epoch commit succeeded but local target key does not match committed rotation; keep pending blocked (group=${groupId} rotation=${activeRotationId} epoch=${targetEpoch})`);
        }
      }
      if (triggerId) {
        this._groupMembershipRotationDone.add(triggerId);
        if (this._groupMembershipRotationDone.size > 2000) {
          this._groupMembershipRotationDone = new Set(Array.from(this._groupMembershipRotationDone).slice(-1000));
        }
      }
    } catch (exc) {
      this._logE2eeError('rotate_epoch', groupId, '', exc as Error);
    }
  }

  /** 将当前 group_secret 通过 P2P E2EE 分发给新成员 */
  private async _distributeKeyToNewMember(groupId: string, newMemberAid: string): Promise<void> {
    try {
      const secretData = this._groupE2ee.loadSecret(groupId);
      if (secretData === null) return;

      // 拉服务端最新成员列表
      const membersResult = await this.call('group.get_members', { group_id: groupId });
      const memberList = isJsonObject(membersResult) && Array.isArray(membersResult.members)
        ? membersResult.members as MemberRecord[]
        : [];
      const memberAids = memberList.map(
        (m) => String(m.aid),
      );

      // 用最新成员列表更新本地当前 epoch 的 member_aids/commitment
      const epoch = secretData.epoch as number;
      const commitment = computeMembershipCommitment(
        memberAids, epoch, groupId, secretData.secret,
      );
      if (this._aid) {
        storeGroupSecret(
          this._keystore, this._aid, groupId, epoch,
          secretData.secret, commitment, memberAids,
        );
      }

      // 构建并签名 manifest
      let manifest = buildMembershipManifest(
        groupId, epoch, epoch, memberAids, {
          added: [newMemberAid],
          removed: [],
          initiatorAid: this._aid ?? '',
        },
      );
      const identity = this._identity;
      if (identity && identity.private_key_pem) {
        manifest = signMembershipManifest(manifest, String(identity.private_key_pem));
      }

      const distPayload = buildKeyDistribution(
        groupId, epoch, secretData.secret,
        memberAids, this._aid ?? '',
        manifest,
        String((secretData as any).epoch_chain ?? ''),
      );
      // 重试 3 次，间隔递增（1s, 2s）
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          await this.call('message.send', {
            to: newMemberAid,
            payload: distPayload,
            encrypt: true,
            persist_required: true,
          });
          break; // 成功则跳出重试循环
        } catch (sendExc) {
          if (attempt < 2) {
            await new Promise(resolve => setTimeout(resolve, (attempt + 1) * 1000));
          } else {
            throw sendExc;
          }
        }
      }
    } catch (exc) {
      this._logE2eeError('distribute_key', groupId, newMemberAid, exc as Error);
    }
  }

  /** 从成员加入事件 payload 中提取新加入的成员 AID 列表。 */
  private _joinedMemberAidsFromPayload(payload: JsonObject): string[] {
    const aids = new Set<string>();
    const addAid = (value: unknown): void => {
      const aid = String(value ?? '').trim();
      if (aid) aids.add(aid);
    };
    addAid(payload.aid ?? payload.applicant_aid ?? (payload as any).applicantAid);
    addAid(payload.actor_aid);
    for (const key of ['member_aid', 'target_aid', 'new_member_aid', 'used_by']) {
      addAid(payload[key]);
    }
    for (const key of ['member', 'request', 'invite_code']) {
      const nested = isJsonObject(payload[key]) ? payload[key] as JsonObject : null;
      if (!nested) continue;
      addAid(nested.aid ?? nested.applicant_aid ?? (nested as any).applicantAid);
      for (const nk of ['member_aid', 'target_aid', 'used_by']) addAid(nested[nk]);
    }
    if (Array.isArray(payload.results)) {
      for (const item of payload.results) {
        if (!isJsonObject(item)) continue;
        const obj = item as JsonObject;
        const status = String(obj.status ?? '').trim().toLowerCase();
        if (status !== 'approved' && obj.approved !== true) continue;
        addAid(obj.aid ?? obj.applicant_aid ?? (obj as any).applicantAid);
        for (const key of ['member_aid', 'target_aid']) addAid(obj[key]);
        for (const key of ['member', 'request']) {
          const nested = isJsonObject(obj[key]) ? obj[key] as JsonObject : null;
          if (!nested) continue;
          addAid(nested.aid ?? nested.applicant_aid);
          for (const nk of ['member_aid', 'target_aid']) addAid(nested[nk]);
        }
      }
    }
    return Array.from(aids);
  }

  // ── 入群密钥恢复策略 ──────────────────────────────────────

  /** 延迟轮换等待时间（毫秒）：给新成员恢复 committed_epoch 的窗口 */
  private static readonly _JOIN_ROTATION_DELAY_MS = 3000;
  // 新成员自身延迟轮换时间：优先让其他在线成员先轮换
  private static readonly _SELF_JOIN_ROTATION_DELAY_MS = 6000;

  /** open/invite_code 入群后延迟轮换。 */
  private async _delayedRotateAfterJoin(groupId: string, triggerId: string, expectedEpoch: number, allowMember = false, delayMs?: number): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, delayMs ?? AUNClient._JOIN_ROTATION_DELAY_MS));
    await this._maybeLeadRotateGroupEpoch(groupId, triggerId, expectedEpoch, allowMember);
  }

  /** 当新成员加入但缺少 old_epoch 时，将当前 epoch 密钥分发给新成员。 */
  private async _maybeBackfillKeyToJoinedMember(groupId: string, payload: JsonObject, triggerId = ''): Promise<void> {
    const memberAids = this._joinedMemberAidsFromPayload(payload)
      .filter(aid => aid && aid !== this._aid);
    if (!groupId || !this._aid || memberAids.length === 0) return;
    if (!this._groupE2ee.hasSecret(groupId)) return;
    for (const memberAid of memberAids) {
      const dedupeKey = `${triggerId || this._membershipRotationTriggerId(groupId, payload)}:backfill:${memberAid}`;
      if (this._groupMemberKeyBackfillDone.has(dedupeKey)) continue;
      this._groupMemberKeyBackfillDone.add(dedupeKey);
      if (this._groupMemberKeyBackfillDone.size > 2000) {
        this._groupMemberKeyBackfillDone = new Set(Array.from(this._groupMemberKeyBackfillDone).slice(-1000));
      }
      await this._distributeKeyToNewMember(groupId, memberAid);
    }
  }


  private _buildRotationSignature(
    groupId: string,
    currentEpoch: number,
    newEpoch: number = 0,
    source?: JsonObject,
  ): Record<string, string> {
    const identity = this._identity;
    if (!identity || !identity.private_key_pem) {
      throw new StateError('rotation signature requires local identity private key');
    }

    const aid = String(identity.aid ?? '');
    const ts = String(Math.floor(Date.now() / 1000));
    let signData: Buffer;
    if (source) {
      const listField = (key: string): string[] => {
        const raw = source[key];
        return Array.isArray(raw)
          ? raw.map(item => String(item ?? '').trim()).filter(Boolean).sort()
          : [];
      };
      signData = Buffer.from(stableStringify({
        version: 'v2',
        group_id: groupId,
        base_epoch: Math.trunc(currentEpoch),
        target_epoch: Math.trunc(newEpoch),
        aid,
        rotation_timestamp: ts,
        rotation_id: String(source.rotation_id ?? source.new_rotation_id ?? ''),
        reason: String(source.reason ?? ''),
        key_commitment: String(source.key_commitment ?? ''),
        manifest_hash: String(source.manifest_hash ?? ''),
        epoch_chain: String(source.epoch_chain ?? ''),
        expected_members: listField('expected_members'),
        required_acks: listField('required_acks'),
      }), 'utf-8');
    } else {
      signData = Buffer.from(`${groupId}|${currentEpoch}|${newEpoch}|${aid}|${ts}`, 'utf-8');
    }
    const privateKey = crypto.createPrivateKey(String(identity.private_key_pem));
    const sig = crypto.sign('SHA256', signData, privateKey);
    const result: Record<string, string> = {
      rotation_signature: sig.toString('base64'),
      rotation_timestamp: ts,
    };
    if (source) result.rotation_sig_version = 'v2';
    return result;
  }

  /** 从 keystore 恢复 SeqTracker 状态 */
  private _restoreSeqTrackerState(): void {
    if (!this._aid) return;
    try {
      // 优先从 seq_tracker 表按行读取
      const loadAll = this._keystore.loadAllSeqs;
      if (typeof loadAll === 'function') {
        const state = loadAll.call(this._keystore, this._aid, this._deviceId, this._slotId);
        if (state && Object.keys(state).length > 0) {
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
          this._seqTracker.restoreState(instanceState.seq_tracker_state as Record<string, number>);
        }
      }
    } catch (exc) {
      this._clientLog.warn(`恢复 SeqTracker 状态失败: ${formatCaughtError(exc)}`);
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
    this._pendingDecryptMsgs.clear();
    this._groupSynced.clear();
    this._p2pSynced = false;
  }

  private _refreshSeqTrackerContext(): void {
    const nextContext = this._currentSeqTrackerContext();
    if (nextContext === this._seqTrackerContext) return;
    this._seqTracker = new SeqTracker();
    this._gapFillDone.clear();
    this._pushedSeqs.clear();
    this._pendingOrderedMsgs.clear();
    this._pendingDecryptMsgs.clear();
    this._groupSynced.clear();
    this._p2pSynced = false;
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
      this._clientLog.warn(`保存 SeqTracker 状态失败: ${formatCaughtError(exc)}`);
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
    const gatewayUrl = this._resolveGateway(params);
    this._gatewayUrl = gatewayUrl;
    this._slotId = String(params.slot_id ?? '');
    this._connectDeliveryMode = { ...(params.delivery_mode ?? this._connectDeliveryMode) };
    const prevState = this._state;
    this._auth.setInstanceContext({ deviceId: this._deviceId, slotId: this._slotId });
    this._state = 'connecting';

    // 前置 restore：在 transport.connect 启动 reader 之前完成，
    // 避免 reader 把积压 push 交给空 tracker 的 handler，触发 S2 历史 gap 误补拉。
    this._refreshSeqTrackerContext();
    this._restoreSeqTrackerState();

    try {
      const challenge = await this._transport.connect(gatewayUrl);
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
        }
      } else {
        await this._auth.initializeWithToken(
          this._transport,
          challenge,
          String(params.access_token),
          {
            deviceId: this._deviceId,
            slotId: this._slotId,
            deliveryMode: this._connectDeliveryMode,
          },
        );
        this._syncIdentityAfterConnect(String(params.access_token));
      }

      this._state = 'connected';
      await this._dispatcher.publish('connection.state', { state: this._state, gateway: gatewayUrl });

      // auth 阶段 aid 可能被 identity 覆盖（上方 this._aid = identity.aid）；
      // 若 context 发生变化，重新 refresh + restore，保持 tracker 与真实身份一致。
      if (this._seqTrackerContext !== this._currentSeqTrackerContext()) {
        this._refreshSeqTrackerContext();
        this._restoreSeqTrackerState();
      }

      this._startBackgroundTasks();

      // 上线后自动上传 prekey
      try {
        await this._uploadPrekey();
      } catch (exc) {
        this._clientLog.warn(`prekey 上传失败: ${formatCaughtError(exc)}`);
      }
    } catch (err) {
      this._state = prevState === 'connected' ? 'disconnected' : 'idle';
      throw err;
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
    return request;
  }

  /** 从参数构建会话选项 */
  private _buildSessionOptions(params: ConnectParams): SessionOptions {
    const options: SessionOptions = {
      auto_reconnect: DEFAULT_SESSION_OPTIONS.auto_reconnect,
      heartbeat_interval: DEFAULT_SESSION_OPTIONS.heartbeat_interval,
      token_refresh_before: DEFAULT_SESSION_OPTIONS.token_refresh_before,
      retry: { ...DEFAULT_SESSION_OPTIONS.retry },
      timeouts: { ...DEFAULT_SESSION_OPTIONS.timeouts },
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
    this._startHeartbeatTask();
    this._startTokenRefreshTask();
    this._startGroupEpochTasks();
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
    if (this._prekeyRefreshTimer !== null) {
      clearInterval(this._prekeyRefreshTimer);
      this._prekeyRefreshTimer = null;
    }
    if (this._groupEpochCleanupTimer !== null) {
      clearInterval(this._groupEpochCleanupTimer);
      this._groupEpochCleanupTimer = null;
    }
    if (this._groupEpochRotateTimer !== null) {
      clearInterval(this._groupEpochRotateTimer);
      this._groupEpochRotateTimer = null;
    }
    if (this._cacheCleanupTimer !== null) {
      clearInterval(this._cacheCleanupTimer);
      this._cacheCleanupTimer = null;
    }
    for (const timer of this._groupEpochRotationRetryTimers.values()) {
      clearTimeout(timer);
    }
    this._groupEpochRotationRetryTimers.clear();
  }

  /** 启动心跳任务 */
  private _startHeartbeatTask(): void {
    if (this._heartbeatTimer !== null) return;
    const rawIntervalSeconds = Number(
      this._sessionOptions.heartbeat_interval ?? DEFAULT_SESSION_OPTIONS.heartbeat_interval,
    );
    if (!Number.isFinite(rawIntervalSeconds) || rawIntervalSeconds <= 0) return;
    const interval = Math.max(rawIntervalSeconds, 30) * 1000;

    // M25: 把连续失败阈值从 3 次收窄到 2 次。既能容忍一次网络抖动/GC 暂停，
    // 又把半开连接的检测延迟从 3 个心跳周期降到 2 个。
    // 真正的 socket 死亡由 ws.on('close') 立即触发 _handleTransportDisconnect，
    // 不依赖此心跳路径。
    let consecutiveFailures = 0;
    const maxFailures = 2;

    this._heartbeatTimer = setInterval(() => {
      if (this._closing || this._state !== 'connected') return;
      this._transport.call('meta.ping', {}).then(() => {
        consecutiveFailures = 0;
      }).catch((exc) => {
        consecutiveFailures++;
        this._clientLog.warn(`心跳失败 (${consecutiveFailures}/${maxFailures}): ${formatCaughtError(exc)}`);
        this._dispatcher.publish('connection.error', { error: formatCaughtError(exc) }).catch(() => {});
        if (consecutiveFailures >= maxFailures) {
          this._clientLog.warn(`连续 ${maxFailures} 次心跳失败，触发断线重连`);
          this._handleTransportDisconnect(exc instanceof Error ? exc : new Error(String(exc)));
        }
      });
    }, interval);
    // 允许 Node.js 进程在只剩定时器时退出
    if (this._heartbeatTimer && typeof this._heartbeatTimer === 'object' && 'unref' in this._heartbeatTimer) {
      (this._heartbeatTimer as NodeJS.Timer).unref();
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
              this._clientLog.warn(`token 刷新连续失败 ${this._tokenRefreshFailures} 次，停止刷新循环并触发重连`);
              await this._dispatcher.publish('token.refresh_exhausted', {
                aid: this._identity?.aid ?? null,
                consecutive_failures: this._tokenRefreshFailures,
                last_error: String(exc),
              });
              this._tokenRefreshFailures = 0;
              this._handleTransportDisconnect(new Error('token refresh exhausted, triggering reconnect'));
              return;
            }
            this._clientLog.debug(`token 刷新失败 (${this._tokenRefreshFailures}/3)，下次重试: ${exc}`);
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

  /** 启动 prekey 刷新任务 */
  private _startPrekeyRefreshTask(): void {
    return;
  }

  private _extractConsumedPrekeyId(message: ConsumedPrekeyCarrier | null | undefined): string {
    if (!message?.e2ee) return '';
    if (message.e2ee.encryption_mode !== 'prekey_ecdh_v2') return '';
    return String(message.e2ee.prekey_id ?? '').trim();
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

  private _schedulePrekeyReplenishIfConsumed(message: ConsumedPrekeyCarrier | null | undefined): void {
    const prekeyId = this._extractConsumedPrekeyId(message);
    if (!prekeyId || this._state !== 'connected') return;
    if (this._prekeyReplenished.has(prekeyId)) return;
    // 同一时刻只允许一个 put_prekey inflight
    if (this._prekeyReplenishInflight.size > 0) return;
    this._prekeyReplenishInflight.add(prekeyId);

    void (async () => {
      try {
        await this._uploadPrekey();
        this._prekeyReplenished.add(prekeyId);
      } catch (exc) {
        this._clientLog.warn(`消费 prekey ${prekeyId} 后补充 current prekey 失败: ${formatCaughtError(exc)}`);
      } finally {
        this._prekeyReplenishInflight.delete(prekeyId);
      }
    })();
  }

  /** 启动群组 epoch 相关后台任务 */
  private _startGroupEpochTasks(): void {
    // 群组 E2EE 是必备能力，始终执行 epoch 清理

    // 旧 epoch 清理（每小时检查一次）
    if (this._groupEpochCleanupTimer === null) {
      this._groupEpochCleanupTimer = setInterval(() => {
        if (this._closing || this._state !== 'connected' || !this._aid) return;
        try {
          const groupIds = typeof this._keystore.listGroupSecretIds === 'function'
            ? this._keystore.listGroupSecretIds(this._aid!)
            : [];
          const retention = this._configModel.oldEpochRetentionSeconds;
          for (const gid of groupIds) {
            this._groupE2ee.cleanup(gid, retention);
          }
        } catch (exc) {
          this._clientLog.warn(`epoch 清理失败: ${formatCaughtError(exc)}`);
        }
      }, 3600_000);
      this._unrefTimer(this._groupEpochCleanupTimer);
    }

    // 定时 epoch 轮换
    const rotateInterval = this._configModel.epochAutoRotateInterval;
    if (rotateInterval > 0 && this._groupEpochRotateTimer === null) {
      this._groupEpochRotateTimer = setInterval(() => {
        if (this._closing || this._state !== 'connected' || !this._aid) return;
        try {
          const groupIds = typeof this._keystore.listGroupSecretIds === 'function'
            ? this._keystore.listGroupSecretIds(this._aid!)
            : [];
          for (const gid of groupIds) {
            this._maybeLeadRotateGroupEpoch(gid).catch((exc) =>
              this._clientLog.warn(`epoch 轮换失败: ${formatCaughtError(exc)}`),
            );
          }
        } catch (exc) {
          this._clientLog.warn(`epoch 轮换失败: ${formatCaughtError(exc)}`);
        }
      }, rotateInterval * 1000);
      this._unrefTimer(this._groupEpochRotateTimer);
    }

    // 内存缓存定时清理（每小时扫描过期条目）
    if (this._cacheCleanupTimer === null) {
      this._cacheCleanupTimer = setInterval(() => {
        const nowSec = Date.now() / 1000;
        // 证书缓存
        for (const [k, v] of this._certCache) {
          if (nowSec >= v.refreshAfter) this._certCache.delete(k);
        }
        // prekey 列表缓存
        for (const [k, v] of this._peerPrekeysCache) {
          if (nowSec >= v.expireAt) this._peerPrekeysCache.delete(k);
        }
        // 补洞去重：清理超过 5 分钟的旧条目（与 Python 对齐，按时间过期）
        const gapCutoffMs = Date.now() - 300_000;
        for (const [k, ts] of this._gapFillDone) {
          if (ts < gapCutoffMs) this._gapFillDone.delete(k);
        }
        // e2ee prekey 缓存
        this._e2ee.cleanExpiredCaches();
        // group e2ee replay guard 缓存
        this._groupE2ee.cleanExpiredCaches();
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
  private static readonly _NO_RECONNECT_CODES = new Set([4001, 4003, 4008, 4009, 4010, 4011]);

  /** 处理服务端主动断开通知 event/gateway.disconnect */
  private _onGatewayDisconnect(data: any): void {
    const code = data?.code;
    const reason = data?.reason ?? '';
    this._clientLog.warn(`服务端主动断开: code=${code}, reason=${reason}`);
    this._serverKicked = true;
  }

  /** 传输层断线回调 */
  private async _handleTransportDisconnect(error: Error | null, closeCode?: number): Promise<void> {
    if (this._closing || this._state === 'closed') return;
    // 已在重连中则跳过，避免心跳超时和 transport 断线回调重复触发
    if (this._reconnectActive) return;
    this._state = 'disconnected';
    this._stopBackgroundTasks();
    await this._dispatcher.publish('connection.state', { state: this._state, error });

    if (!this._sessionOptions.auto_reconnect) return;
    if (this._reconnectActive) return;
    // 不重连 close code（认证失败/权限错误/被踢等）或服务端通知断开：抑制重连
    if (this._serverKicked || (closeCode !== undefined && AUNClient._NO_RECONNECT_CODES.has(closeCode))) {
      this._state = 'terminal_failed';
      const reason = this._serverKicked ? 'server kicked' : `close code ${closeCode}`;
      this._clientLog.warn(`抑制自动重连: ${reason}`);
      await this._dispatcher.publish('connection.state', {
        state: this._state, error, reason,
      });
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
    this._reconnectLoop(serverInitiated).catch((exc) => {
      this._clientLog.warn(`重连循环异常: ${formatCaughtError(exc)}`);
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
    return result;
  }

  /**
   * 为已有普通群绑定命名 AID（升级为命名群）。
   */
  async bindGroupAid(groupId: string, groupName: string): Promise<Record<string, unknown>> {
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
    return result;
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
