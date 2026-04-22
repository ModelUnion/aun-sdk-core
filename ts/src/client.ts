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
import { E2EEManager, type PrekeyMaterial } from './e2ee.js';
import {
  GroupE2EEManager,
  computeMembershipCommitment,
  storeGroupSecret,
  buildKeyDistribution,
  buildMembershipManifest,
  signMembershipManifest,
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
import { AUNLogger } from './logger.js';
import { SQLiteBackup } from './keystore/sqlite-backup.js';

import { AuthNamespace } from './namespaces/auth.js';
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

// ── 日志辅助 ──────────────────────────────────────────────────

/** 文件日志（模块级单例） */
let _debugLogger: AUNLogger | null = null;

/** 简易日志：前缀 [aun_core.client] */
function _clientLog(
  level: string,
  msg: string,
  ...args: Array<string | number | boolean | null | undefined | Error | object>
): void {
  const ts = new Date().toISOString();
  const formatted = args.reduce<string>((s, a) => s.replace('%s', String(a)), msg);
  // eslint-disable-next-line no-console
  console.log(`[${ts}] [aun_core.client] ${level}: ${formatted}`);
  if (_debugLogger) _debugLogger.log(`${level}: ${formatted}`);
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
  token_refresh_before: 60.0,
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

/** 需要客户端签名的关键方法 */
const SIGNED_METHODS = new Set([
  'group.send', 'group.kick', 'group.add_member',
  'group.leave', 'group.remove_member', 'group.update_rules',
  'group.update', 'group.update_announcement',
  'group.update_join_requirements', 'group.set_role',
  'group.transfer_owner', 'group.review_join_request',
  'group.batch_review_join_request',
  'group.request_join', 'group.use_invite_code',
  'group.resources.put', 'group.resources.update',
  'group.resources.delete', 'group.resources.request_add',
  'group.resources.direct_add', 'group.resources.approve_request',
  'group.resources.reject_request',
]);

/** peer 证书缓存 TTL（10 分钟） */
const PEER_CERT_CACHE_TTL = 600;

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

  /** 补洞去重：已完成/进行中的 key -> 开始时间戳，防止重复 pull 同一区间 */
  private _gapFillDone: Map<string, number> = new Map();
  /** 推送路径已分发的 seq 集合（按命名空间），补洞路径 publish 前检查以避免重复分发 */
  private _pushedSeqs: Map<string, Set<number>> = new Map();

  // ── 后台任务定时器 ──────────────────────────────────────────
  private _heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private _tokenRefreshTimer: ReturnType<typeof setTimeout> | null = null;
  private _prekeyRefreshTimer: ReturnType<typeof setInterval> | null = null;
  private _groupEpochCleanupTimer: ReturnType<typeof setInterval> | null = null;
  private _groupEpochRotateTimer: ReturnType<typeof setInterval> | null = null;
  private _cacheCleanupTimer: ReturnType<typeof setInterval> | null = null;
  private _reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private _reconnecting = false;
  private _serverKicked = false;

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

    // 初始化文件日志（仅 debug 模式）
    if (debug) {
      _debugLogger = new AUNLogger();
      _clientLog('info', 'AUNClient 初始化完成 (debug=true, aunPath=%s)', this._configModel.aunPath);
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
    });

    this._transport = new RPCTransport({
      eventDispatcher: this._dispatcher,
      timeout: 10_000,
      onDisconnect: (err, closeCode) => this._handleTransportDisconnect(err, closeCode),
      verifySsl: this._configModel.verifySsl,
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
    // 内部订阅：推送消息自动解密后 re-publish 给用户
    this._dispatcher.subscribe('_raw.message.received', (data) => this._onRawMessageReceived(data));
    // 群组消息推送：自动解密后 re-publish
    this._dispatcher.subscribe('_raw.group.message_created', (data) => this._onRawGroupMessageCreated(data));
    // 群组变更事件：拦截处理成员变更触发的 epoch 轮换，然后透传
    this._dispatcher.subscribe('_raw.group.changed', (data) => this._onRawGroupChanged(data));
    // 其他事件直接透传
    for (const evt of ['message.recalled', 'message.ack']) {
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

  /** 向 gatewayUrl 的 /health 端点发送 HEAD 请求，检查网关可用性 */
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
    await this._connectOnce(normalized, false);
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
      this._resetSeqTrackingState();
      return;
    }
    await this._transport.close();
    const closableKeyStore = this._keystore as KeyStore & { close?: () => void };
    closableKeyStore.close?.();
    this._state = 'closed';
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

    // 自动加密：message.send 默认加密（encrypt 默认 True）
    if (method === 'message.send') {
      const encrypt = p.encrypt ?? true;
      delete p.encrypt;
      if (encrypt) {
        return await this._sendEncrypted(p);
      }
    }

    // 自动加密：group.send 默认加密（encrypt 默认 True）
    if (method === 'group.send') {
      const encrypt = p.encrypt ?? true;
      delete p.encrypt;
      if (encrypt) {
        return await this._sendGroupEncrypted(p);
      }
    }

    // 关键操作自动附加客户端签名
    if (SIGNED_METHODS.has(method)) {
      this._signClientOperation(method, p);
    }

    let result = await this._transport.call(method, p);

    // 自动解密：message.pull 返回的消息
    if (method === 'message.pull' && isJsonObject(result)) {
      const r = result;
      const messages = r.messages;
      if (Array.isArray(messages) && messages.length > 0) {
        r.messages = await this._decryptMessages(messages.filter(isJsonObject) as Message[]);
        if (this._aid) {
          const ns = `p2p:${this._aid}`;
          this._seqTracker.onPullResult(ns, messages.filter(isJsonObject));
          // ⚠️ 逻辑边界 L1/L3：P2P retention floor 通道 = server_ack_seq
          // 服务端在持久化/设备视图分支返回 server_ack_seq，客户端若 contiguous 落后必须 force 跳过
          // retention window 外的空洞。与 S2 [1,seq-1] 历史 gap 配合；若去掉 force，首条消息建的 gap 会
          // 永远悬挂触发无限 pull。临时消息淘汰走 ephemeral_earliest_available_seq（当前仅提示），与此互斥。
          const serverAck = Number(r.server_ack_seq ?? 0);
          if (serverAck > 0) {
            const contig = this._seqTracker.getContiguousSeq(ns);
            if (contig < serverAck) {
              _clientLog('info', 'message.pull retention-floor 推进: ns=%s contiguous=%d -> server_ack_seq=%d', ns, contig, serverAck);
              this._seqTracker.forceContiguousSeq(ns, serverAck);
            }
          }
          this._saveSeqTrackerState();
          // auto-ack contiguous_seq
          const contig = this._seqTracker.getContiguousSeq(ns);
          if (contig > 0) {
            this._transport.call('message.ack', {
              seq: contig,
              device_id: this._deviceId,
            }).catch((e) => { _clientLog('debug', 'message.pull auto-ack 失败: %s', formatCaughtError(e)); });
          }
        }
      }
    }

    // 自动解密：group.pull 返回的群消息
    if (method === 'group.pull' && isJsonObject(result)) {
      const r = result;
      const messages = r.messages;
      if (Array.isArray(messages) && messages.length > 0) {
        r.messages = await this._decryptGroupMessages(messages.filter(isJsonObject) as Message[]);
        const gid = (p.group_id ?? '') as string;
        if (gid) {
          const ns = `group:${gid}`;
          this._seqTracker.onPullResult(ns, messages.filter(isJsonObject));
          // ⚠️ 逻辑边界 L4：group retention floor 通道 = cursor.current_seq
          // 群路径目前无独立 earliest_available_seq 字段；若未来引入 group retention，需新增字段并同步更新此处。
          // 与 S2 [1,seq-1] 历史 gap 配合使用，force_contiguous_seq 是跳过空洞的唯一手段。
          const cursor = isJsonObject(r.cursor) ? r.cursor : null;
          if (cursor) {
            const serverAck = Number(cursor.current_seq ?? 0);
            if (serverAck > 0) {
              const contig = this._seqTracker.getContiguousSeq(ns);
              if (contig < serverAck) {
                _clientLog('info', 'group.pull retention-floor 推进: ns=%s contiguous=%d -> cursor.current_seq=%d', ns, contig, serverAck);
                this._seqTracker.forceContiguousSeq(ns, serverAck);
              }
            }
          }
          this._saveSeqTrackerState();
          // auto-ack contiguous_seq
          const contig = this._seqTracker.getContiguousSeq(ns);
          if (contig > 0) {
            this._transport.call('group.ack_messages', {
              group_id: gid,
              msg_seq: contig,
              device_id: this._deviceId,
            }).catch((e) => { _clientLog('debug', 'group.pull auto-ack 失败: group=%s %s', gid, formatCaughtError(e)); });
          }
        }
      }
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
            // 同步到服务端：将服务端 epoch 从 0 推到 1
            this._syncEpochToServer(gid).catch((exc) =>
              this._logE2eeError('sync_epoch', gid, '', exc as Error),
            );
          } catch (exc) {
            this._logE2eeError('create_epoch', gid, '', exc as Error);
          }
        }
      }

      // 加人后自动分发密钥给新成员（仅 RPC 成功时）
      if (method === 'group.add_member' && isJsonObject(result) && !result.error) {
        const groupId = String(p.group_id ?? '');
        const newAid = String(p.aid ?? '');
        if (groupId && newAid) {
          if (this._configModel.rotateOnJoin) {
            this._rotateGroupEpoch(groupId).catch((exc) =>
              this._logE2eeError('rotate_epoch', groupId, '', exc as Error),
            );
          } else {
            this._distributeKeyToNewMember(groupId, newAid).catch((exc) =>
              this._logE2eeError('distribute_key', groupId, newAid, exc as Error),
            );
          }
        }
      }

      // 审批通过后自动分发密钥给新成员
      if (method === 'group.review_join_request' && isJsonObject(result)) {
        if (result.approved || result.status === 'approved') {
          const groupId = String(p.group_id ?? '');
          const newAid = String(p.aid ?? '');
          if (groupId && newAid) {
            this._distributeKeyToNewMember(groupId, newAid).catch((exc) =>
              this._logE2eeError('distribute_key', groupId, newAid, exc as Error),
            );
          }
        }
      }

      // 批量审批通过后分发密钥
      if (method === 'group.batch_review_join_request' && isJsonObject(result)) {
        const groupId = String(p.group_id ?? '');
        const approvedAids = ((Array.isArray(result.results) ? result.results : []) as GroupBatchReviewResult[])
          .filter((item) => item.ok && item.status === 'approved' && item.aid)
          .map((item) => String(item.aid));
        if (groupId && approvedAids.length > 0) {
          if (this._configModel.rotateOnJoin) {
            this._rotateGroupEpoch(groupId).catch((exc) =>
              this._logE2eeError('rotate_epoch', groupId, '', exc as Error),
            );
          } else {
            for (const aid of approvedAids) {
              this._distributeKeyToNewMember(groupId, aid).catch((exc) =>
                this._logE2eeError('distribute_key', groupId, aid, exc as Error),
              );
            }
          }
        }
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

  // ── E2EE 加密发送 ────────────────────────────────────────

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

    const recipientPrekeys = await this._fetchPeerPrekeys(toAid);
    const selfSyncCopies = await this._buildSelfSyncCopies({
      logicalToAid: toAid,
      payload,
      messageId,
      timestamp,
    });

    if (recipientPrekeys.length <= 1 && selfSyncCopies.length === 0) {
      return await this._sendEncryptedSingle({
        toAid,
        payload,
        messageId,
        timestamp,
        prekey: recipientPrekeys[0],
      });
    }

    const recipientCopies = await this._buildRecipientDeviceCopies({
      toAid,
      payload,
      messageId,
      timestamp,
      prekeys: recipientPrekeys,
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
    return await this._transport.call('message.send', sendParams);
  }

  private async _sendEncryptedSingle(opts: {
    toAid: string;
    payload: JsonObject;
    messageId: string;
    timestamp: number;
    prekey?: PrekeyMaterial | null;
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
    return await this._transport.call('message.send', sendParams);
  }

  private async _buildRecipientDeviceCopies(opts: {
    toAid: string;
    payload: JsonObject;
    messageId: string;
    timestamp: number;
    prekeys: PrekeyMaterial[];
  }): Promise<JsonObject[]> {
    const recipientCopies: JsonObject[] = [];
    const certCache = new Map<string, string>();
    for (const prekey of opts.prekeys) {
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
  }): Promise<JsonObject[]> {
    const myAid = this._aid;
    if (!myAid) {
      return [];
    }
    const prekeys = await this._fetchPeerPrekeys(myAid);
    if (prekeys.length === 0) {
      return [];
    }
    const copies: JsonObject[] = [];
    for (const prekey of prekeys) {
      const deviceId = String((prekey as JsonObject).device_id ?? '').trim();
      if (deviceId === this._deviceId) {
        continue;
      }
      const peerCertPem = await this._resolveSelfCopyPeerCert(
        String(prekey.cert_fingerprint ?? '').trim().toLowerCase() || undefined,
      );
      const [envelope, encryptResult] = this._encryptCopyPayload({
        logicalToAid: opts.logicalToAid,
        payload: opts.payload,
        peerCertPem,
        prekey,
        messageId: opts.messageId,
        timestamp: opts.timestamp,
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
  }): [JsonObject, JsonObject] {
    const [envelope, encryptResult] = this._e2ee.encryptOutbound(
      opts.logicalToAid,
      opts.payload,
      opts.peerCertPem,
      opts.prekey ?? null,
      opts.messageId,
      opts.timestamp,
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
        _clientLog('warn', '发布 e2ee.degraded 事件失败: %s', formatCaughtError(exc));
      });
    }
  }

  /** 自动加密并发送群组消息 */
  private async _sendGroupEncrypted(params: RpcParams): Promise<RpcResult> {
    const groupId = String(params.group_id ?? '');
    const payload = isJsonObject(params.payload) ? params.payload : null;
    if (!groupId) {
      throw new ValidationError('group.send requires group_id');
    }
    if (payload === null) {
      throw new ValidationError('group.send payload must be an object when encrypt=true');
    }

    const envelope = this._groupE2ee.encrypt(groupId, payload);

    const sendParams: RpcParams = {
      group_id: groupId,
      payload: envelope,
      type: 'e2ee.group_encrypted',
      encrypted: true,
    };
    // 注入 device_id（与 call() 路径对齐）
    if (this._deviceId && sendParams.device_id === undefined) {
      sendParams.device_id = this._deviceId;
    }
    this._signClientOperation('group.send', sendParams);
    return await this._transport.call('group.send', sendParams);
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
      _clientLog('warn', 'P2P 消息解密失败: %s', formatCaughtError(exc));
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
        this._dispatcher.publish('message.undecryptable', safeEvent).catch(() => {});
      }
    });
  }

  /** 实际处理推送消息的异步任务 */
  private async _processAndPublishMessage(data: EventPayload): Promise<void> {
    if (!isJsonObject(data)) {
      await this._dispatcher.publish('message.received', data);
      return;
    }
    const msg: Message = { ...data };

    // 拦截 P2P 传输的群组密钥分发/请求/响应消息
    if (await this._tryHandleGroupKeyMessage(msg)) {
      return;
    }

    // P2P 空洞检测
    const seq = msg.seq as number | undefined;
    if (seq !== undefined && seq !== null && this._aid) {
      const ns = `p2p:${this._aid}`;
      const needPull = this._seqTracker.onMessageSeq(ns, seq);
      if (needPull) {
        this._fillP2pGap().catch(exc => _clientLog('warn', '后台补洞触发失败: %s', formatCaughtError(exc)));
      }
      // auto-ack contiguous_seq
      const contig = this._seqTracker.getContiguousSeq(ns);
      if (contig > 0) {
        this._transport.call('message.ack', {
          seq: contig,
          device_id: this._deviceId,
        }).catch((e) => { _clientLog('debug', 'P2P auto-ack 失败: %s', formatCaughtError(e)); });
      }
      // 即时持久化 cursor，异常断连后不回退
      this._saveSeqTrackerState();
    }

    const decrypted = await this._decryptSingleMessage(msg);
    // 记录已推送的 seq，补洞路径据此去重
    if (seq !== undefined && seq !== null && this._aid) {
      const ns = `p2p:${this._aid}`;
      if (!this._pushedSeqs.has(ns)) this._pushedSeqs.set(ns, new Set());
      this._pushedSeqs.get(ns)!.add(seq);
    }
    await this._dispatcher.publish('message.received', decrypted);
  }

  /** 处理群组消息推送：自动解密后 re-publish */
  private async _onRawGroupMessageCreated(data: EventPayload): Promise<void> {
    this._processAndPublishGroupMessage(data).catch((exc) => {
      _clientLog('warn', '群消息解密失败: %s', formatCaughtError(exc));
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
        this._dispatcher.publish('group.message_undecryptable', safeEvent).catch(() => {});
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
      await this._dispatcher.publish('group.message_created', data);
      return;
    }
    const msg: Message = { ...data };
    const groupId = (msg.group_id ?? '') as string;
    const seq = msg.seq as number | undefined;
    const payload = msg.payload;

    // 空洞检测（无论带不带 payload 都检查）
    if (groupId && seq !== undefined && seq !== null) {
      const ns = `group:${groupId}`;
      const needPull = this._seqTracker.onMessageSeq(ns, seq);
      if (needPull) {
        this._fillGroupGap(groupId).catch(exc => _clientLog('warn', '后台补洞触发失败: %s', formatCaughtError(exc)));
      }
      // auto-ack contiguous_seq
      const contig = this._seqTracker.getContiguousSeq(ns);
      if (contig > 0) {
        this._transport.call('group.ack_messages', {
          group_id: groupId,
          msg_seq: contig,
          device_id: this._deviceId,
        }).catch((e) => { _clientLog('debug', '群消息 auto-ack 失败: group=%s %s', groupId, formatCaughtError(e)); });
      }
      // 即时持久化 cursor，异常断连后不回退
      this._saveSeqTrackerState();
    }

    if (payload === undefined || payload === null
      || (typeof payload === 'object' && Object.keys(payload as object).length === 0)) {
      // 不带 payload 的通知：自动 pull 最新消息
      await this._autoPullGroupMessages(msg);
      return;
    }
    const decrypted = await this._decryptGroupMessage(msg);
    // 记录已推送的 seq，补洞路径据此去重
    if (groupId && seq !== undefined && seq !== null) {
      const nsKey = `group:${groupId}`;
      if (!this._pushedSeqs.has(nsKey)) this._pushedSeqs.set(nsKey, new Set());
      this._pushedSeqs.get(nsKey)!.add(seq);
    }
    await this._dispatcher.publish('group.message_created', decrypted);
  }

  /** 收到不带 payload 的 group.message_created 通知后，自动 pull 最新消息 */
  private async _autoPullGroupMessages(notification: Message): Promise<void> {
    const groupId = (notification.group_id ?? '') as string;
    if (!groupId) {
      await this._dispatcher.publish('group.message_created', notification);
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
          // pushedSeqs 去重：跳过已通过推送路径分发的消息
          const pushed = this._pushedSeqs.get(ns);
          for (const msg of messages) {
            if (isJsonObject(msg)) {
              const s = (msg as Record<string, unknown>).seq as number | undefined;
              if (pushed && s !== undefined && s !== null && pushed.has(s)) {
                continue; // 已通过推送路径分发，跳过
              }
              await this._dispatcher.publish('group.message_created', msg);
            }
          }
          this._prunePushedSeqs(ns);
          return;
        }
      }
    } catch (exc) {
      _clientLog('debug', '自动 pull 群消息失败: %s', formatCaughtError(exc));
    }
    await this._dispatcher.publish('group.message_created', notification);
  }

  /** 后台补齐群消息空洞 */
  private async _fillGroupGap(groupId: string): Promise<void> {
    const ns = `group:${groupId}`;
    const afterSeq = this._seqTracker.getContiguousSeq(ns);
    // 新设备（seq=0）没有历史 epoch key，拉旧消息也解不了
    if (afterSeq === 0 && !this._groupE2ee.hasSecret(groupId)) {
      return;
    }
    // 去重：同一 (group:id:after_seq) 只补一次
    const dedupKey = `group_msg:${groupId}:${afterSeq}`;
    if (this._gapFillDone.has(dedupKey)) return;
    this._gapFillDone.set(dedupKey, Date.now());
    // S1: 成功/失败双路径都需要根据"是否真正前进"决定是否保留 dedup 标记，
    // 避免 pull 返空、contiguous 未推进时标记被永久污染。
    let success = false;
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
              await this._dispatcher.publish('group.message_created', msg);
            }
          }
          this._prunePushedSeqs(ns);
        }
      }
      success = true;
    } catch (exc) {
      _clientLog('warn', '群消息补洞失败: %s', formatCaughtError(exc));
    } finally {
      // S1: 仅当 contiguous 已真正越过 afterSeq 时才保留标记；
      // 否则（异常 / 空结果）清除，避免后续相同 after_seq 的补洞被跳过。
      const contigAfter = this._seqTracker.getContiguousSeq(ns);
      if (!success || contigAfter <= afterSeq) {
        this._gapFillDone.delete(dedupKey);
      }
    }
  }

  /** 后台补齐 P2P 消息空洞 */
  private async _fillP2pGap(): Promise<void> {
    if (!this._aid) return;
    const ns = `p2p:${this._aid}`;
    const afterSeq = this._seqTracker.getContiguousSeq(ns);
    // 新设备（seq=0）没有历史 prekey，拉旧消息也解不了
    if (afterSeq === 0) {
      return;
    }
    // 去重：同一 (type:after_seq) 只补一次
    const dedupKey = `p2p:${afterSeq}`;
    if (this._gapFillDone.has(dedupKey)) return;
    this._gapFillDone.set(dedupKey, Date.now());
    // S1: 成功路径也要判断是否真正前进；pull 返空时必须清除标记，
    // 否则下一次相同 afterSeq 触发的补洞会被永久跳过。
    let success = false;
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
              await this._dispatcher.publish('message.received', msg);
            }
          }
          this._prunePushedSeqs(ns);
        }
      }
      success = true;
    } catch (exc) {
      _clientLog('warn', 'P2P 消息补洞失败: %s', formatCaughtError(exc));
    } finally {
      // S1: contiguous 未越过 afterSeq → 清除标记，允许后续重试
      const contigAfter = this._seqTracker.getContiguousSeq(ns);
      if (!success || contigAfter <= afterSeq) {
        this._gapFillDone.delete(dedupKey);
      }
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

  /** 后台补齐群事件空洞 */
  private async _fillGroupEventGap(groupId: string): Promise<void> {
    const ns = `group_event:${groupId}`;
    const afterSeq = this._seqTracker.getContiguousSeq(ns);
    // 去重：同一 (group_evt:id:after_seq) 只补一次
    const dedupKey = `group_evt:${groupId}:${afterSeq}`;
    if (this._gapFillDone.has(dedupKey)) return;
    this._gapFillDone.set(dedupKey, Date.now());
    // S1: 成功/失败均按"是否真正前进"决定是否保留标记
    let success = false;
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
          // 持久化 cursor + ack_events（与 Python 对齐）
          this._saveSeqTrackerState();
          const contig = this._seqTracker.getContiguousSeq(ns);
          if (contig > 0) {
            this._transport.call('group.ack_events', {
              group_id: groupId,
              event_seq: contig,
              device_id: this._deviceId,
            }).catch((e) => { _clientLog('debug', '群事件 auto-ack 失败: group=%s %s', groupId, formatCaughtError(e)); });
          }
          for (const evt of events) {
            if (isJsonObject(evt)) {
              evt._from_gap_fill = true;
              const et = String(evt.event_type ?? '');
              // 消息事件由 _fillGroupGap 负责，事件补洞不重复投递
              if (et === 'group.message_created') continue;
              // group.changed 或缺失/其他 → 发布到 group.changed（向后兼容）
              await this._dispatcher.publish('group.changed', evt);
            }
          }
        }
      }
      success = true;
    } catch (exc) {
      _clientLog('warn', '群事件补洞失败: %s', formatCaughtError(exc));
    } finally {
      const contigAfter = this._seqTracker.getContiguousSeq(ns);
      if (!success || contigAfter <= afterSeq) {
        this._gapFillDone.delete(dedupKey);
      }
    }
  }

  /**
   * 上线/重连后一次性同步所有已加入群：
   * 1. 有 epoch key 的群 → 补消息 + 补事件
   * 2. 无 epoch key 的群 → 仅补事件（事件不加密，等推送触发密钥恢复）
   */
  private async _syncAllGroupsOnce(): Promise<void> {
    try {
      const result = await this.call('group.list_my', {});
      if (!isJsonObject(result)) return;
      const items = result.items;
      if (!Array.isArray(items)) return;
      for (const g of items) {
        if (isJsonObject(g)) {
          const gid = String(g.group_id ?? '');
          if (gid) {
            // 有 epoch key → 补消息
            if (this._groupE2ee.hasSecret(gid)) {
              await this._fillGroupGap(gid);
            }
            // 所有群都补事件（事件不加密）
            await this._fillGroupEventGap(gid);
          }
        }
      }
    } catch (exc) {
      _clientLog('debug', '批量同步群失败: %s', formatCaughtError(exc));
    }
  }

  /**
   * 处理群组变更事件：透传给用户，并在成员离开/被踢时自动触发 epoch 轮换。
   * 按协议，轮换由剩余在线 admin/owner 负责。
   */
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
          }).catch((e) => { _clientLog('debug', '群事件推送 auto-ack 失败: group=%s %s', groupId, formatCaughtError(e)); });
        }
      }

      // 仅在真实 event gap 时才触发补拉（补洞回来的事件不再触发新补洞）
      if (needPull && groupId && !d._from_gap_fill) {
        this._fillGroupEventGap(groupId).catch(exc => _clientLog('warn', '后台补洞触发失败: %s', formatCaughtError(exc)));
      }

      // 成员退出或被踢 → 剩余 admin/owner 自动补位轮换
      // H21: 避免 epoch 轮换风暴——所有剩余 admin 同时收到事件不能都发起轮换，
      // 否则 CAS 冲突激增。策略：本地 AID 为"排序最小 admin"时才发起，其他 admin
      // 叠加随机 jitter 作为超时兜底（本地最小 admin 失败时由下一位顶上）。
      if (d.action === 'member_left' || d.action === 'member_removed') {
        if (groupId) {
          this._maybeLeadRotateGroupEpoch(groupId).catch((exc) =>
            this._logE2eeError('rotate_epoch', groupId, '', exc as Error),
          );
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
   * 成员退出/被踢后，判断本地是否为 leader admin 并发起 epoch 轮换。
   * 避免所有剩余 admin 同时触发 `_rotateGroupEpoch` 造成 CAS 风暴。
   */
  private async _maybeLeadRotateGroupEpoch(groupId: string): Promise<void> {
    const myAid = this._aid;
    if (!myAid) return;
    try {
      const membersResp = await this.call('group.get_members', { group_id: groupId });
      if (!isJsonObject(membersResp)) return;
      const rawList = membersResp.members ?? membersResp.items;
      if (!Array.isArray(rawList)) return;
      const admins: string[] = [];
      for (const m of rawList) {
        if (!isJsonObject(m)) continue;
        const role = String(m.role ?? '');
        const aid = String(m.aid ?? '');
        if (aid && (role === 'admin' || role === 'owner')) admins.push(aid);
      }
      if (admins.length === 0) return;
      admins.sort();
      const leader = admins[0];
      if (leader === myAid) {
        // 我是 leader，直接发起
        await this._rotateGroupEpoch(groupId);
        return;
      }
      if (!admins.includes(myAid)) return;
      // 非 leader：随机 jitter（2~6s）后查询服务端 epoch 是否已被 leader 推进
      const jitterMs = 2000 + Math.floor(Math.random() * 4000);
      let beforeEpoch = 0;
      try {
        const resp = await this.call('group.e2ee.get_epoch', { group_id: groupId });
        if (isJsonObject(resp)) beforeEpoch = Number(resp.epoch ?? 0);
      } catch { beforeEpoch = (await this._groupE2ee.currentEpoch(groupId)) ?? 0; }
      await new Promise((r) => setTimeout(r, jitterMs));
      let afterEpoch = 0;
      try {
        const resp = await this.call('group.e2ee.get_epoch', { group_id: groupId });
        if (isJsonObject(resp)) afterEpoch = Number(resp.epoch ?? 0);
      } catch { afterEpoch = (await this._groupE2ee.currentEpoch(groupId)) ?? 0; }
      if (afterEpoch > beforeEpoch) return; // leader 已完成
      _clientLog('info', '[H21] leader 未完成 epoch 轮换，非 leader 兜底: group=%s myAid=%s', groupId, myAid);
      await this._rotateGroupEpoch(groupId);
    } catch (exc) {
      _clientLog('warn', '_maybeLeadRotateGroupEpoch 失败: %s', formatCaughtError(exc));
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
      _clientLog('warn', '清理解散群组 %s epoch 密钥失败: %s', groupId, formatCaughtError(exc));
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

    _clientLog('info', '已清理解散群组 %s 的本地状态', groupId);
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
          _clientLog('warn', '验签失败：证书指纹不匹配 aid=%s', sigAid);
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
        _clientLog('warn', '群事件验签失败 aid=%s method=%s', sigAid, method);
      }
      return ok;
    } catch (exc) {
      _clientLog('warn', '群事件验签异常: %s', formatCaughtError(exc));
      return false;
    }
  }

  /** 尝试处理 P2P 传输的群组密钥消息。返回 true 表示已处理（不再传播）。 */
  private async _tryHandleGroupKeyMessage(message: Message): Promise<boolean> {
    const payload = message.payload;
    if (!isJsonObject(payload)) return false;

    const payloadObj = payload;

    // S14: 控制面消息类型识别。一旦命中（明文 type 或 P2P 解密后内层 type），无论后续
    // 处理是否成功都返回 true，避免控制面消息被发布到业务消息流。
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
      // S14: P2P 解密失败仍未识别为控制面 — 保持原行为返回 false
      if (decrypted === null) return false;
      this._schedulePrekeyReplenishIfConsumed(decrypted);
      actualPayload = isJsonObject(decrypted.payload) ? decrypted.payload : null;
      if (actualPayload === null) return false;
      const innerType = actualPayload.type;
      if (typeof innerType === 'string' && GROUP_KEY_TYPES.has(innerType)) {
        isControlPlane = true;
      }
    }

    const result = this._groupE2ee.handleIncoming(actualPayload);
    // S14: 非控制面消息且 handleIncoming 不识别 → 不拦截
    if (!isControlPlane && result === null) return false;

    if (result === 'request') {
      // 处理密钥请求并回复
      const groupId = String(actualPayload.group_id ?? '');
      const requester = String(actualPayload.requester_aid ?? '');
      let members = this._groupE2ee.getMemberAids(groupId);

      // 请求者不在本地成员列表时，回源查询服务端最新成员列表
      if (requester && !members.includes(requester)) {
        try {
          const membersResult = await this.call('group.get_members', { group_id: groupId });
          const memberList = isJsonObject(membersResult) && Array.isArray(membersResult.members)
            ? membersResult.members as MemberRecord[]
            : [];
          members = memberList.map(
            (m) => String(m.aid),
          );
          // 更新本地当前 epoch 的 member_aids/commitment
          if (members.includes(requester)) {
            const secretData = this._groupE2ee.loadSecret(groupId);
            if (secretData && this._aid) {
              const epoch = secretData.epoch as number;
              const commitment = computeMembershipCommitment(
                members, epoch, groupId, secretData.secret,
              );
              storeGroupSecret(
                this._keystore, this._aid, groupId, epoch,
                secretData.secret, commitment, members,
              );
            }
          }
        } catch (exc) {
          _clientLog('warn', '群组 %s 成员列表回源失败: %s', groupId, formatCaughtError(exc));
        }
      }

      const response = this._groupE2ee.handleKeyRequestMsg(actualPayload, members);
      if (response && requester) {
        try {
          await this.call('message.send', {
            to: requester,
            payload: response,
            encrypt: true,
          });
        } catch (exc) {
          _clientLog('warn', '向 %s 回复群组密钥失败: %s', requester, formatCaughtError(exc));
        }
      }
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
      _clientLog(
        'error',
        '写入证书到 keystore 失败 (aid=%s, fp=%s): %s',
        aid,
        certFingerprint ?? '',
        formatCaughtError(exc),
      );
    }

    return certPem;
  }

  /** 获取对方所有设备的 prekey 列表。 */
  private async _fetchPeerPrekeys(peerAid: string): Promise<PrekeyMaterial[]> {
    const cachedList = this._peerPrekeysCache.get(peerAid);
    if (cachedList && Date.now() / 1000 < cachedList.expireAt) {
      return cachedList.items.map((item) => ({ ...item }));
    }
    const cached = this._e2ee.getCachedPrekey(peerAid);
    if (cached !== null) return [{ ...cached }];

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
        const normalized: PrekeyMaterial[] = [];
        for (const item of devicePrekeys) {
          if (!isPeerPrekeyMaterial(item)) {
            continue;
          }
          normalized.push({ ...item });
        }
        if (normalized.length > 0) {
          this._peerPrekeysCache.set(peerAid, {
            items: normalized.map((item) => ({ ...item })),
            expireAt: Date.now() / 1000 + 300,
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
        this._peerPrekeysCache.set(peerAid, {
          items: [{ ...prekey }],
          expireAt: Date.now() / 1000 + 300,
        });
        this._e2ee.cachePrekey(peerAid, prekey);
        return [{ ...prekey }];
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
      return { ...cachedList.items[0] };
    }
    const prekeys = await this._fetchPeerPrekeys(peerAid);
    if (prekeys.length === 0) {
      return null;
    }
    return { ...prekeys[0] };
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
        _clientLog('debug', '刷新发送方 %s 证书失败，继续使用已验证的内存缓存: %s', aid, formatCaughtError(exc));
        return true;
      }
      _clientLog('warn', '获取发送方 %s 证书失败且无已验证缓存，拒绝信任: %s', aid, formatCaughtError(exc));
      return false;
    }
  }

  /**
   * 获取经过 PKI 验证的 peer 证书（仅信任内存缓存中已验证的证书）。
   * 零信任：不直接信任 keystore 中可能由恶意服务端注入的证书。
   */
  private _getVerifiedPeerCert(aid: string, certFingerprint?: string): string | null {
    const cached = this._certCache.get(AUNClient._certCacheKey(aid, certFingerprint));
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
        _clientLog('warn', '无法获取发送方 %s 的证书，跳过解密', fromAid);
        return message;
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
        const fromAid = String(msg.from ?? '');
        const senderCertFingerprint = String(
          payload.sender_cert_fingerprint ?? (payload.aad as JsonObject | undefined)?.sender_cert_fingerprint ?? '',
        ).trim().toLowerCase();
        if (fromAid) {
          const certReady = await this._ensureSenderCertCached(fromAid, senderCertFingerprint || undefined);
          if (!certReady) {
            _clientLog('warn', '无法获取发送方 %s 的证书，跳过解密', fromAid);
            result.push(msg);
            continue;
          }
        }
        // 用 _decryptMessage 而非 decryptMessage，避免消耗 seen set
        const decrypted = this._e2ee._decryptMessage(msg);
        if (decrypted !== null) {
          result.push(decrypted);
        } else {
          // TS-015: 解密失败不回退到密文，跳过该消息并记录
          _clientLog('warn', 'pull 消息解密失败，跳过: from=%s mid=%s', msg.from, msg.message_id);
        }
      } else {
        result.push(msg);
      }
    }
    return result;
  }

  /** 解密单条群组消息。opts.skipReplay 用于 group.pull 场景跳过防重放。 */
  private async _decryptGroupMessage(
    message: Message,
    opts?: { skipReplay?: boolean },
  ): Promise<Message> {
    const payload = message.payload;
    if (!isJsonObject(payload)) return message;
    const payloadObj = payload;
    if (payloadObj.type !== 'e2ee.group_encrypted') return message;

    // 确保发送方证书已缓存（签名验证需要）
    const senderAid = String(message.from ?? message.sender_aid ?? '');
    if (senderAid) {
      const certOk = await this._ensureSenderCertCached(senderAid);
      if (!certOk) {
        _clientLog('warn', '群消息解密跳过：发送方 %s 证书不可用', senderAid);
        return message;
      }
    }

    // 先尝试直接解密
    const result = this._groupE2ee.decrypt(message, opts);
    if (result !== null && result.e2ee) {
      return result;
    }

    // 解密失败，尝试密钥恢复后重试
    const groupId = String(message.group_id ?? '');
    const sender = String(message.from ?? message.sender_aid ?? '');
    const epoch = payloadObj.epoch as number | undefined;
    if (epoch != null && groupId) {
      const recovery = this._groupE2ee.buildRecoveryRequest(groupId, epoch, sender);
      if (recovery) {
        try {
          await this.call('message.send', {
            to: recovery.to,
            payload: recovery.payload,
            encrypt: true,
          });
        } catch (exc) {
          _clientLog('debug', '密钥恢复请求失败: %s', formatCaughtError(exc));
        }
      }
    }

    return message;
  }

  /** 批量解密群组消息（用于 group.pull，跳过防重放） */
  private async _decryptGroupMessages(messages: Message[]): Promise<Message[]> {
    const result: Message[] = [];
    for (const msg of messages) {
      const decrypted = await this._decryptGroupMessage(msg, { skipReplay: true });
      result.push(decrypted);
    }
    return result;
  }

  // ── Group E2EE 编排 ───────────────────────────────────────

  /** 建群后将本地 epoch 1 同步到服务端（服务端初始为 0） */
  /** 建群后将本地 epoch 1 同步到服务端（服务端初始为 0），最多重试 3 次 */
  private async _syncEpochToServer(groupId: string): Promise<void> {
    const maxRetries = 3;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const rotateParams: RpcParams = {
          group_id: groupId,
          current_epoch: 0,
        };
        Object.assign(rotateParams, this._buildRotationSignature(groupId, 0, 1));
        await this.call('group.e2ee.rotate_epoch', rotateParams);
        return;
      } catch (exc) {
        if (attempt < maxRetries) {
          const delay = 500 * Math.pow(2, attempt - 1);
          _clientLog('warn', '同步 epoch 到服务端失败 (group=%s, 第%d/%d次): %s, %dms后重试',
            groupId, attempt, maxRetries, formatCaughtError(exc), delay);
          await new Promise(r => setTimeout(r, delay));
        } else {
          _clientLog('error', '同步 epoch 到服务端最终失败 (group=%s, 已重试%d次): %s',
            groupId, maxRetries, formatCaughtError(exc));
        }
      }
    }
  }

  /**
   * 为指定群组轮换 epoch 并分发新密钥。
   * 使用服务端 CAS 保证只有一方成功。
   */
  private async _rotateGroupEpoch(groupId: string): Promise<void> {
    try {
      // 1. 读取服务端当前 epoch
      const epochResult = await this.call('group.e2ee.get_epoch', { group_id: groupId });
      const currentEpoch = isJsonObject(epochResult) && typeof epochResult.epoch === 'number'
        ? epochResult.epoch
        : 0;

      // 2. CAS 尝试递增
      const rotateParams: RpcParams = {
        group_id: groupId,
        current_epoch: currentEpoch,
      };
      Object.assign(rotateParams, this._buildRotationSignature(groupId, currentEpoch, currentEpoch + 1));
      const casResult = await this.call('group.e2ee.rotate_epoch', rotateParams);
      if (!isJsonObject(casResult) || !casResult.success) return;

      const newEpoch = typeof casResult.epoch === 'number' ? casResult.epoch : 0;

      // 3. 获取最新成员列表
      const membersResult = await this.call('group.get_members', { group_id: groupId });
      const memberList = isJsonObject(membersResult) && Array.isArray(membersResult.members)
        ? membersResult.members as MemberRecord[]
        : [];
      const memberAids = memberList.map(
        (m) => String(m.aid),
      );

      // 4. 本地生成密钥 + 存储 + 分发
      const info = this._groupE2ee.rotateEpochTo(groupId, newEpoch, memberAids);
      const distributions = (Array.isArray(info.distributions) ? info.distributions : []) as GroupDistribution[];
      for (const dist of distributions) {
        // 重试 3 次，间隔递增（1s, 2s）
        for (let attempt = 0; attempt < 3; attempt++) {
          try {
            await this.call('message.send', {
              to: dist.to,
              payload: dist.payload,
              encrypt: true,
            });
            break; // 成功则跳出重试循环
          } catch (exc) {
            if (attempt < 2) {
              await new Promise(resolve => setTimeout(resolve, (attempt + 1) * 1000));
            } else {
              _clientLog('warn', 'epoch 密钥分发失败 (to=%s): %s', dist.to, formatCaughtError(exc));
            }
          }
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
      );
      // 重试 3 次，间隔递增（1s, 2s）
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          await this.call('message.send', {
            to: newMemberAid,
            payload: distPayload,
            encrypt: true,
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

  /** 构建 epoch 轮换签名参数。失败时抛错，调用方需在 try/catch 中决定是否跳过轮换。 */
  private _buildRotationSignature(
    groupId: string,
    currentEpoch: number,
    newEpoch: number = 0,
  ): Record<string, string> {
    const identity = this._identity;
    if (!identity || !identity.private_key_pem) {
      throw new StateError('rotation signature requires local identity private key');
    }

    const aid = String(identity.aid ?? '');
    const ts = String(Math.floor(Date.now() / 1000));
    const signData = Buffer.from(`${groupId}|${currentEpoch}|${newEpoch}|${aid}|${ts}`, 'utf-8');
    const privateKey = crypto.createPrivateKey(String(identity.private_key_pem));
    const sig = crypto.sign('SHA256', signData, privateKey);
    return {
      rotation_signature: sig.toString('base64'),
      rotation_timestamp: ts,
    };
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
      _clientLog('warn', '恢复 SeqTracker 状态失败: %s', formatCaughtError(exc));
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
  }

  private _refreshSeqTrackerContext(): void {
    const nextContext = this._currentSeqTrackerContext();
    if (nextContext === this._seqTrackerContext) return;
    this._seqTracker = new SeqTracker();
    this._gapFillDone.clear();
    this._pushedSeqs.clear();
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
      _clientLog('warn', '保存 SeqTracker 状态失败: %s', formatCaughtError(exc));
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
            if (_debugLogger) _debugLogger.setAid(` [${this._aid}]`);
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
        _clientLog('warn', 'prekey 上传失败: %s', formatCaughtError(exc));
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
    if (_debugLogger) _debugLogger.setAid(` [${this._aid}]`);
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
    // 上线/重连后一次性补齐群消息和群事件
    this._syncAllGroupsOnce().catch(exc => _clientLog('warn', '后台补洞触发失败: %s', formatCaughtError(exc)));
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
  }

  /** 启动心跳任务 */
  private _startHeartbeatTask(): void {
    if (this._heartbeatTimer !== null) return;
    const interval = Number(this._sessionOptions.heartbeat_interval ?? 30) * 1000;
    if (interval <= 0) return;

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
        _clientLog('warn', '心跳失败 (%s/%s): %s', consecutiveFailures, maxFailures, formatCaughtError(exc));
        this._dispatcher.publish('connection.error', { error: formatCaughtError(exc) }).catch(() => {});
        if (consecutiveFailures >= maxFailures) {
          _clientLog('warn', '连续 %s 次心跳失败，触发断线重连', maxFailures);
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
    const lead = Number(this._sessionOptions.token_refresh_before ?? 60);
    const minimumSleep = 1000;

    const scheduleNext = (): void => {
      if (this._closing) return;
      if (this._state !== 'connected' || !this._gatewayUrl) {
        this._tokenRefreshTimer = setTimeout(scheduleNext, minimumSleep);
        this._unrefTimer(this._tokenRefreshTimer);
        return;
      }

      let identity = this._identity ?? this._auth.loadIdentityOrNone() ?? null;
      if (identity === null) {
        this._tokenRefreshTimer = setTimeout(scheduleNext, minimumSleep);
        this._unrefTimer(this._tokenRefreshTimer);
        return;
      }
      this._identity = identity;

      const expiresAt = this._auth.getAccessTokenExpiry(identity);
      if (expiresAt === null) {
        this._tokenRefreshTimer = setTimeout(scheduleNext, minimumSleep);
        this._unrefTimer(this._tokenRefreshTimer);
        return;
      }

      const delay = Math.max((expiresAt - lead - Date.now() / 1000) * 1000, minimumSleep);
      this._tokenRefreshTimer = setTimeout(async () => {
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
        } catch (exc) {
          if (exc instanceof AuthError) {
            _clientLog('debug', 'token 刷新失败，下次重试: %s', exc);
          } else {
            await this._dispatcher.publish('connection.error', { error: formatCaughtError(exc) });
          }
        }
        scheduleNext();
      }, delay);
      this._unrefTimer(this._tokenRefreshTimer);
    };

    scheduleNext();
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
        _clientLog('warn', '消费 prekey %s 后补充 current prekey 失败: %s', prekeyId, formatCaughtError(exc));
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
          const allGroups = typeof this._keystore.loadAllGroupSecretStates === 'function'
            ? this._keystore.loadAllGroupSecretStates(this._aid!) ?? {}
            : {};
          const retention = this._configModel.oldEpochRetentionSeconds;
          for (const gid of Object.keys(allGroups)) {
            this._groupE2ee.cleanup(gid, retention);
          }
        } catch (exc) {
          _clientLog('warn', 'epoch 清理失败: %s', formatCaughtError(exc));
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
          const allGroups = typeof this._keystore.loadAllGroupSecretStates === 'function'
            ? this._keystore.loadAllGroupSecretStates(this._aid!) ?? {}
            : {};
          for (const gid of Object.keys(allGroups)) {
            this._rotateGroupEpoch(gid).catch((exc) =>
              _clientLog('warn', 'epoch 轮换失败: %s', formatCaughtError(exc)),
            );
          }
        } catch (exc) {
          _clientLog('warn', 'epoch 轮换失败: %s', formatCaughtError(exc));
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
    _clientLog('warn', '服务端主动断开: code=%s, reason=%s', code, reason);
    this._serverKicked = true;
  }

  /** 传输层断线回调 */
  private async _handleTransportDisconnect(error: Error | null, closeCode?: number): Promise<void> {
    if (this._closing || this._state === 'closed') return;
    // 已在重连中则跳过，避免心跳超时和 transport 断线回调重复触发
    if (this._reconnecting) return;
    this._state = 'disconnected';
    this._stopBackgroundTasks();
    await this._dispatcher.publish('connection.state', { state: this._state, error });

    if (!this._sessionOptions.auto_reconnect) return;
    if (this._reconnecting) return;
    // 不重连 close code（认证失败/权限错误/被踢等）或服务端通知断开：抑制重连
    if (this._serverKicked || (closeCode !== undefined && AUNClient._NO_RECONNECT_CODES.has(closeCode))) {
      this._state = 'terminal_failed';
      const reason = this._serverKicked ? 'server kicked' : `close code ${closeCode}`;
      _clientLog('warn', '抑制自动重连: %s', reason);
      await this._dispatcher.publish('connection.state', {
        state: this._state, error, reason,
      });
      return;
    }
    // 1000 = 正常关闭, 1006 = 网络异常断开（无 close frame），其他 code = 服务端主动关闭
    const serverInitiated = closeCode !== undefined && closeCode !== 1000 && closeCode !== 1006;
    this._startReconnect(serverInitiated);
  }

  /** 启动重连循环（默认无限重试 + 指数退避 + Full Jitter，仅在不可重试错误、close() 或 max_attempts 耗尽时终止） */
  private _startReconnect(serverInitiated = false): void {
    if (this._reconnecting) return;
    this._reconnecting = true;

    const retry = this._sessionOptions.retry;
    const maxDelay = Number(retry.max_delay ?? 64.0) * 1000;
    // M25: max_attempts=0 表示无限重试（与 Go/Python 对齐）
    const maxAttemptsRaw = Number(retry.max_attempts ?? 0);
    const maxAttempts = Number.isFinite(maxAttemptsRaw) && maxAttemptsRaw > 0 ? Math.floor(maxAttemptsRaw) : 0;
    // 服务端主动关闭（close frame）时从 16s 起跳，避免重连风暴；网络断开从 1s 起跳
    const baseDelay = serverInitiated ? 16_000 : Number(retry.initial_delay ?? 1.0) * 1000;
    let delay = baseDelay;
    let attempt = 0;

    const tryReconnect = async (): Promise<void> => {
      attempt++;
      if (this._closing) {
        this._reconnecting = false;
        return;
      }

      this._state = 'reconnecting';
      await this._dispatcher.publish('connection.state', {
        state: this._state,
        attempt,
      });

      // Full Jitter: random(0, delay) 打散重连时机
      this._reconnectTimer = setTimeout(async () => {
        // 防止 close() 后仍执行重连（递归调用无 await 可能越过 _stopReconnect）
        if (this._closing || !this._reconnecting) {
          this._reconnecting = false;
          return;
        }
        try {
          // 重连前先 HEAD /health 探测，不健康则跳过本轮
          if (this._gatewayUrl) {
            const healthy = await this._discovery.checkHealth(this._gatewayUrl, 5_000);
            if (!healthy) {
              delay = Math.random() * Math.min(delay * 2, maxDelay);
              if (!this._closing && this._reconnecting) {
                tryReconnect().catch(() => {});
              } else {
                this._reconnecting = false;
              }
              return;
            }
          }
          await this._transport.close();
          if (this._sessionParams === null) {
            throw new StateError('missing connect params for reconnect');
          }
          await this._connectOnce(this._sessionParams, true);
          this._reconnecting = false;
          this._reconnectTimer = null;
        } catch (exc) {
          await this._dispatcher.publish('connection.error', {
            error: formatCaughtError(exc),
            attempt,
          });
          if (!AUNClient._shouldRetryReconnect(exc as Error)) {
            this._state = 'terminal_failed';
            this._reconnecting = false;
            await this._dispatcher.publish('connection.state', {
              state: this._state,
              error: formatCaughtError(exc),
              attempt,
            });
            return;
          }
          // M25: 仅在显式配置 max_attempts > 0 且已达到上限时，进入 terminal_failed
          if (maxAttempts > 0 && attempt >= maxAttempts) {
            this._state = 'terminal_failed';
            this._reconnecting = false;
            await this._dispatcher.publish('connection.state', {
              state: this._state,
              error: formatCaughtError(exc),
              attempt,
              reason: 'max_attempts_exhausted',
            });
            return;
          }
          delay = Math.random() * Math.min(delay * 2, maxDelay);
          if (!this._closing && this._reconnecting) {
            tryReconnect().catch(() => {}); // 捕获未处理的 rejection
          } else {
            this._reconnecting = false;
          }
        }
      }, Math.random() * delay);
      this._unrefTimer(this._reconnectTimer);
    };

    tryReconnect();
  }

  /** 停止重连 */
  private _stopReconnect(): void {
    if (this._reconnectTimer !== null) {
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
    }
    this._reconnecting = false;
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
