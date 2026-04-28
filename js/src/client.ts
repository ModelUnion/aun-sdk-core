// ── AUNClient（SDK 主入口 — 浏览器完整实现）──────────────────
// 对标 Python client.py，浏览器环境适配：
//   - 所有密码学操作异步（SubtleCrypto）
//   - HTTP 使用 fetch() 而非 Node http
//   - 无文件系统（IndexedDB via keystore）
//   - 后台任务使用 setTimeout/setInterval

import { createConfig, getDeviceId, normalizeInstanceId, type AUNConfig } from './config.js';
import { EventDispatcher, type EventPayload, type EventHandler, type Subscription } from './events.js';
import { GatewayDiscovery } from './discovery.js';
import { RPCTransport } from './transport.js';
import { AuthFlow } from './auth.js';
import { SeqTracker } from './seq-tracker.js';
import { AuthNamespace } from './namespaces/auth.js';
import { CustodyNamespace } from './namespaces/custody.js';
import { CryptoProvider, uint8ToBase64, base64ToUint8, pemToArrayBuffer, p1363ToDer, toBufferSource } from './crypto.js';
import {
  E2EEManager,
  type PrekeyMaterial,
  _certificateSha256Fingerprint as certificateSha256Fingerprint,
  _ecdsaVerifyDer as ecdsaVerifyDer,
  _importCertPublicKeyEcdsa as importCertPublicKeyEcdsa,
} from './e2ee.js';
import {
  GroupE2EEManager,
  computeMembershipCommitment,
  storeGroupSecret,
  buildKeyDistribution,
  buildKeyRequest,
  buildMembershipManifest,
  signMembershipManifest,
} from './e2ee-group.js';
import { IndexedDBKeyStore } from './keystore/indexeddb.js';
import type { KeyStore } from './keystore/index.js';
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
  type IdentityRecord,
  type JsonObject,
  type JsonValue,
  type Message,
  type ConnectionState,
  type MetadataRecord,
  type RpcParams,
  type RpcResult,
} from './types.js';

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

const RECONNECT_MIN_BASE_DELAY_SECONDS = 1.0;
const RECONNECT_MAX_BASE_DELAY_SECONDS = 64.0;
const GROUP_ROTATION_LEASE_MS = 120_000;
const GROUP_ROTATION_RETRY_MAX_DELAY_MS = 300_000;

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
const PEER_CERT_CACHE_TTL = 600;

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

/**
 * AUN Core SDK 客户端 — 浏览器版本。
 *
 * 职责：
 *   - 连接管理（WebSocket + 自动重连 + 指数退避）
 *   - 认证（token 初始化 / 多策略认证 / token 刷新）
 *   - RPC 调用（JSON-RPC 2.0）
 *   - E2EE 自动编排（加密/解密/密钥管理/group 生命周期）
 *   - 事件分发与管道
 *   - 后台任务（心跳、token 刷新、prekey 轮换、epoch 清理/轮换）
 *
 */
export class AUNClient {
  /** SDK 配置模型 */
  readonly configModel: AUNConfig;
  /** 原始配置字典 */
  readonly config: RpcParams;

  private _aid: string | null = null;
  private _identity: IdentityRecord | null = null;
  private _state: 'idle' | 'connecting' | 'authenticating' | 'connected' | 'disconnected' | 'reconnecting' | 'closed' | 'terminal_failed' = 'idle';
  private _gatewayUrl: string | null = null;
  private _deviceId: string;
  private _slotId: string;
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
  private _e2ee: E2EEManager;
  private _groupE2ee: GroupE2EEManager;

  /** 认证命名空间 */
  readonly auth: AuthNamespace;
  /** AID 托管命名空间 */
  readonly custody: CustodyNamespace;

  // E2EE 编排状态（内存缓存）
  private _certCache: Map<string, CachedPeerCert> = new Map();
  private _prekeyReplenishInflight: Set<string> = new Set();
  private _prekeyReplenished: Set<string> = new Set();
  private _peerPrekeysCache: Map<string, CachedPeerPrekeys> = new Map();

  // 后台任务 handle（浏览器 setInterval/setTimeout）
  private _heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private _tokenRefreshTimer: ReturnType<typeof setTimeout> | null = null;
  /** 非连接状态下 token 刷新的退避计数器 */
  private _tokenDisconnectedRetries = 0;
  private _prekeyRefreshTimer: ReturnType<typeof setTimeout> | null = null;
  private _groupEpochCleanupTimer: ReturnType<typeof setInterval> | null = null;
  private _groupEpochRotateTimer: ReturnType<typeof setInterval> | null = null;
  private _cacheCleanupTimer: ReturnType<typeof setInterval> | null = null;
  /** 消息序列号跟踪器（群消息 + P2P 空洞检测） */
  private _seqTracker: SeqTracker = new SeqTracker();
  private _seqTrackerContext: string | null = null;
  /** 补洞去重：已完成/进行中的 key 集合，防止重复 pull 同一区间 */
  private _gapFillDone: Set<string> = new Set();
  /** 推送路径已分发的 seq 集合（按命名空间），补洞路径 publish 前检查以避免重复分发 */
  private _pushedSeqs: Map<string, Set<number>> = new Map();
  private _pendingDecryptMsgs: Map<string, JsonObject[]> = new Map();
  private _groupEpochRotationInflight: Set<string> = new Set();
  private _groupEpochRecoveryInflight: Map<string, Promise<boolean>> = new Map();
  private _groupMembershipRotationDone: Set<string> = new Set();
  private _groupEpochRotationRetryTimers: Map<string, ReturnType<typeof setTimeout>> = new Map();
  /** Lazy group sync：首次发送群消息前自动拉取历史 */
  private _groupSynced: Set<string> = new Set();
  /** Lazy P2P sync：首次发送 P2P 消息前自动拉取历史 */
  private _p2pSynced = false;
  /** gap fill 来源标记：true 表示当前正在补洞（pull 触发），false 表示非补洞 */
  private _gapFillActive = false;
  // 重连相关
  private _reconnectActive = false;
  private _reconnectAbort: AbortController | null = null;
  private _serverKicked = false;

  constructor(config?: Partial<AUNConfig> & RpcParams, _debug = false) {
    const rawConfig: RpcParams = config ?? {};
    this.configModel = createConfig(rawConfig as Partial<AUNConfig>);
    this.config = {
      aun_path: this.configModel.aunPath,
      root_ca_path: this.configModel.rootCaPem,
      seed_password: this.configModel.seedPassword,
    };

    this._dispatcher = new EventDispatcher();
    this._discovery = new GatewayDiscovery();
    this._keystore = new IndexedDBKeyStore();
    this._deviceId = getDeviceId();
    this._slotId = '';
    this._connectDeliveryMode = normalizeDeliveryModeConfig({ mode: 'fanout' });
    this._defaultConnectDeliveryMode = { ...this._connectDeliveryMode };
    this._auth = new AuthFlow({
      keystore: this._keystore,
      crypto: new CryptoProvider(),
      aid: null,
      deviceId: this._deviceId,
      slotId: this._slotId,
      rootCaPem: this.configModel.rootCaPem,
      verifySsl: this.configModel.verifySsl,
    });
    this._transport = new RPCTransport({
      eventDispatcher: this._dispatcher,
      timeout: DEFAULT_SESSION_OPTIONS.timeouts.call,
      onDisconnect: (error, closeCode) => this._handleTransportDisconnect(error, closeCode),
    });
    this._e2ee = new E2EEManager({
      identityFn: () => this._identity ?? {},
      deviceIdFn: () => this._deviceId,
      keystore: this._keystore,
      replayWindowSeconds: this.configModel.replayWindowSeconds,
    });
    this._groupE2ee = new GroupE2EEManager({
      identityFn: () => this._identity ?? {},
      keystore: this._keystore,
      // 零信任：只返回经 PKI 验证的内存缓存证书
      senderCertResolver: (aid: string) => this._getVerifiedPeerCert(aid),
      initiatorCertResolver: (aid: string) => this._getVerifiedPeerCert(aid),
    });

    this.auth = new AuthNamespace(this);
    this.custody = new CustodyNamespace(this);

    // 内部订阅：推送消息自动解密后 re-publish 给用户
    this._dispatcher.subscribe('_raw.message.received', (data) => {
      this._onRawMessageReceived(data);
    });
    // 群组消息推送：自动解密后 re-publish
    this._dispatcher.subscribe('_raw.group.message_created', (data) => {
      this._onRawGroupMessageCreated(data);
    });
    // 群组变更事件：拦截处理成员变更触发的 epoch 轮换，然后透传
    this._dispatcher.subscribe('_raw.group.changed', (data) => {
      this._onRawGroupChanged(data);
    });
    // 其他事件直接透传
    for (const evt of ['message.recalled', 'message.ack']) {
      this._dispatcher.subscribe(`_raw.${evt}`, (data) => {
        this._dispatcher.publish(evt, data);
      });
    }
    // 服务端主动断开通知：记录日志并标记不重连
    this._dispatcher.subscribe('_raw.gateway.disconnect', (data) => {
      this._onGatewayDisconnect(data);
    });
  }

  // ── 属性 ──────────────────────────────────────────

  get aid(): string | null {
    return this._aid;
  }

  get state(): ConnectionState {
    return this._state;
  }

  get gatewayUrl(): string | null {
    return this._gatewayUrl;
  }

  set gatewayUrl(url: string | null) {
    this._gatewayUrl = url;
  }

  get discovery(): GatewayDiscovery {
    return this._discovery;
  }

  /** 最近一次 health check 结果，null 表示尚未检查 */
  get gatewayHealth(): boolean | null {
    return this._discovery.lastHealthy;
  }

  /** 主动检查 gateway 可用性（GET /health） */
  async checkGatewayHealth(gatewayUrl: string, timeout = 5000): Promise<boolean> {
    return this._discovery.checkHealth(gatewayUrl, timeout);
  }

  get e2ee(): E2EEManager {
    return this._e2ee;
  }

  get groupE2ee(): GroupE2EEManager {
    return this._groupE2ee;
  }

  // ── 生命周期 ──────────────────────────────────────

  /**
   * 连接到 Gateway。
   *
   * @param auth - 认证参数，必须包含 access_token 和 gateway
   * @param options - 可选的会话选项（auto_reconnect, heartbeat_interval 等）
   */
  async connect(
    auth: RpcParams,
    options?: RpcParams,
  ): Promise<void> {
    if (this._state !== 'idle' && this._state !== 'closed' && this._state !== 'disconnected') {
      throw new StateError(`connect not allowed in state ${this._state}`);
    }

    const params = { ...auth, ...options };
    const normalized = this._normalizeConnectParams(params);
    this._sessionParams = normalized;
    this._sessionOptions = this._buildSessionOptions(normalized);
    this._transport.setTimeout(this._sessionOptions.timeouts.call);
    this._closing = false;

    await this._connectOnce(normalized, false);
  }

  /** 断开连接但保留本地状态，可再次 connect */
  async disconnect(): Promise<void> {
    if (this._state !== 'connected' && this._state !== 'reconnecting') {
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
    await this._dispatcher.publish('connection.state', { state: this._state });
  }

  /** 列出本地所有已存储的身份摘要（仅返回有有效私钥的 AID） */
  async listIdentities(): Promise<Array<{ aid: string; metadata?: MetadataRecord }>> {
    const listFn = (this._keystore as any).listIdentities;
    if (typeof listFn !== 'function') return [];
    const aids: string[] = await listFn.call(this._keystore);
    const summaries: Array<{ aid: string; metadata?: MetadataRecord }> = [];
    for (const aid of [...aids].sort()) {
      const identity = await this._keystore.loadIdentity(aid);
      if (!identity || !identity.private_key_pem) continue;
      const summary: { aid: string; metadata?: MetadataRecord } = { aid };
      // 优先从 loadMetadata 获取
      const loadMeta = (this._keystore as any).loadMetadata;
      if (typeof loadMeta === 'function') {
        const md = await loadMeta.call(this._keystore, aid);
        if (md && Object.keys(md).length > 0) { summary.metadata = md; }
      }
      // 回退：从 identity 中提取非核心字段
      if (!summary.metadata) {
        const metadata: MetadataRecord = {};
        for (const [key, value] of Object.entries(identity)) {
          if (!['aid', 'private_key_pem', 'public_key_der_b64', 'curve', 'cert'].includes(key)) {
            metadata[key] = value;
          }
        }
        if (Object.keys(metadata).length > 0) { summary.metadata = metadata; }
      }
      summaries.push(summary);
    }
    return summaries;
  }

  /** 关闭连接 */
  async close(): Promise<void> {
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
    await this._dispatcher.publish('connection.state', { state: this._state });
    this._resetSeqTrackingState();
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

    // 自动加密：message.send 默认加密（encrypt 默认 true）
    if (method === 'message.send') {
      const encrypt = p.encrypt !== undefined ? p.encrypt : true;
      delete p.encrypt;
      if (encrypt) {
        return this._sendEncrypted(p);
      }
    }

    // 自动加密：group.send 默认加密（encrypt 默认 true）
    if (method === 'group.send') {
      const encrypt = p.encrypt !== undefined ? p.encrypt : true;
      delete p.encrypt;
      if (encrypt) {
        return this._sendGroupEncrypted(p);
      }
    }

    // 关键操作自动附加客户端签名
    if (SIGNED_METHODS.has(method)) {
      await this._signClientOperation(method, p);
    }

    const result = await this._transport.call(method, p);

    // 自动解密：message.pull 返回的消息
    if (method === 'message.pull' && isJsonObject(result)) {
      const r = result;
      const messages = r.messages;
      const rawMessages = (Array.isArray(messages) ? messages : []).filter(isJsonObject) as Message[];
      if (rawMessages.length) {
        r.messages = await this._decryptMessages(rawMessages);
      }
      if (this._aid) {
        const ns = `p2p:${this._aid}`;
        // 用原始 messages 喂 SeqTracker（解密去重前），与 Go/TS/Python 一致
        if (rawMessages.length) {
          this._seqTracker.onPullResult(ns, rawMessages);
        }
        // ⚠️ 逻辑边界 L1/L3：P2P retention floor 通道 = server_ack_seq
        // 服务端在持久化/设备视图分支返回 server_ack_seq，客户端若 contiguous 落后必须 force 跳过
        // retention window 外的空洞。与 S2 [1,seq-1] 历史 gap 配合；若去掉 force，首条消息建的 gap 会
        // 永远悬挂触发无限 pull。临时消息淘汰走 ephemeral_earliest_available_seq（仅提示），与此互斥。
        const serverAck = Number(r.server_ack_seq ?? 0);
        if (serverAck > 0) {
          const contig = this._seqTracker.getContiguousSeq(ns);
          if (contig < serverAck) {
            console.info('[aun_core] message.pull retention-floor 推进: ns=' + ns + ' contiguous=' + contig + ' -> server_ack_seq=' + serverAck);
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
          }).catch((e) => { console.warn('message.pull auto-ack 失败:', e); });
        }
      }
    }

    // 自动解密：group.pull 返回的群消息
    if (method === 'group.pull' && isJsonObject(result)) {
      const r = result;
      const messages = r.messages;
      // 先保存原始消息（解密前），用于喂 SeqTracker（与 P2P message.pull 路径对齐）
      const rawMessages = (Array.isArray(messages) ? messages : []).filter(isJsonObject) as Message[];
      if (rawMessages.length) {
        r.messages = await this._decryptGroupMessages(rawMessages);
      }
      const gid = (p.group_id ?? '') as string;
      if (gid) {
        const ns = `group:${gid}`;
        // ⚠️ 使用原始消息（rawMessages）喂 SeqTracker，与 P2P message.pull 路径一致
        if (rawMessages.length) {
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
              console.info('[aun_core] group.pull retention-floor 推进: ns=' + ns + ' contiguous=' + contig + ' -> cursor.current_seq=' + serverAck);
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
          }).catch((e) => { console.warn('group.pull auto-ack 失败: group=' + gid, e); });
        }
      }
    }

    // ── Group E2EE 自动编排 ────────────────────────────
    // ── Group E2EE 自动编排（必备能力，始终启用）────────
    {
      // 建群后自动创建 epoch（幂等：已有 secret 时跳过）
      if (method === 'group.create' && isJsonObject(result)) {
        const group = isJsonObject(result.group) ? result.group as GroupRecord : null;
        const gid = String(group?.group_id ?? '');
        if (gid && this._aid && !(await this._groupE2ee.hasSecret(gid))) {
          try {
            await this._groupE2ee.createEpoch(gid, [this._aid]);
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
        this._safeAsync(this._maybeLeadRotateGroupEpoch(
          groupId,
          this._membershipRotationTriggerId(groupId, result),
          expectedEpoch,
        ));
      }
    }

    return result;
  }

  // ── 便利方法 ──────────────────────────────────────

  async ping(params?: RpcParams): Promise<RpcResult> {
    return this.call('meta.ping', params ?? {});
  }

  async status(params?: RpcParams): Promise<RpcResult> {
    return this.call('meta.status', params ?? {});
  }

  async trustRoots(params?: RpcParams): Promise<RpcResult> {
    return this.call('meta.trust_roots', params ?? {});
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

  /** 处理 transport 层推送的原始消息：解密后 re-publish 给用户 */
  private _onRawMessageReceived(data: EventPayload): void {
    this._safeAsync(this._processAndPublishMessage(data));
  }

  /** 实际处理推送消息的异步任务 */
  private async _processAndPublishMessage(data: EventPayload): Promise<void> {
    try {
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
      // 推送路径收到 P2P 消息 → 标记已同步，后续发送无需再 lazySyncP2p
      this._p2pSynced = true;
      if (seq !== undefined && seq !== null && this._aid) {
        const ns = `p2p:${this._aid}`;
        const needPull = this._seqTracker.onMessageSeq(ns, seq);
        if (needPull) {
          this._safeAsync(this._fillP2pGap());
        }
        // auto-ack contiguous_seq
        const contig = this._seqTracker.getContiguousSeq(ns);
        if (contig > 0) {
          this._transport.call('message.ack', {
            seq: contig,
            device_id: this._deviceId,
          }).catch((e) => { console.warn('P2P auto-ack 失败:', e); });
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
    } catch (exc) {
      console.warn('消息解密失败:', exc);
      // H26: 解密失败不再投递原始密文 payload（避免元数据泄漏 + 语义混淆），
      // 改为发布 message.undecryptable 事件，仅携带安全的 header 信息。
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
        await this._dispatcher.publish('message.undecryptable', safeEvent);
      }
    }
  }

  /** 处理群组消息推送：自动解密后 re-publish */
  private _onRawGroupMessageCreated(data: EventPayload): void {
    this._safeAsync(this._processAndPublishGroupMessage(data));
  }

  /**
   * 处理群组推送消息的异步任务。
   *
   * 带 payload 的事件（消息推送）：解密后 re-publish。
   * 不带 payload 的事件（通知）：自动 pull 最新消息，逐条解密后 re-publish。
   */
  private async _processAndPublishGroupMessage(data: EventPayload): Promise<void> {
    try {
      if (!isJsonObject(data)) {
        await this._dispatcher.publish('group.message_created', data);
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
          this._safeAsync(this._fillGroupGap(groupId));
        }
        const contig = this._seqTracker.getContiguousSeq(ns);
        if (contig > 0) {
          this._transport.call('group.ack_messages', {
            group_id: groupId,
            msg_seq: contig,
            device_id: this._deviceId,
            slot_id: this._slotId,
          }).catch((e) => { console.warn('群消息 auto-ack 失败: group=' + groupId, e); });
        }
        this._saveSeqTrackerState();
      }

      // 记录已推送的 seq，补洞路径据此去重
      if (groupId && seq !== undefined && seq !== null) {
        const nsKey = `group:${groupId}`;
        if (!this._pushedSeqs.has(nsKey)) this._pushedSeqs.set(nsKey, new Set());
        this._pushedSeqs.get(nsKey)!.add(seq);
      }

      // R3: 解密失败 → 不 publish 密文给应用层，入 pending 队列 + 发 undecryptable 事件
      const payloadForCheck = isJsonObject(msg.payload) ? msg.payload : null;
      if (payloadForCheck?.type === 'e2ee.group_encrypted' && !decrypted.e2ee) {
        if (groupId) this._enqueuePendingDecrypt(groupId, msg);
        await this._dispatcher.publish('group.message_undecryptable', {
          message_id: msg.message_id ?? null,
          group_id: groupId,
          from: msg.from ?? null,
          seq,
          timestamp: msg.timestamp ?? null,
          _decrypt_error: 'group secret unavailable',
        } as Record<string, JsonValue>);
        return;
      }

      await this._dispatcher.publish('group.message_created', decrypted);
    } catch (exc) {
      console.warn('群消息解密失败:', exc);
      // H26: 解密失败改发 group.message_undecryptable 事件，不投递原始密文 payload。
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
        await this._dispatcher.publish('group.message_undecryptable', safeEvent);
      }
    }
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
          // ⚠️ 不再重复调用 onPullResult：call('group.pull') 拦截器已在内部调用过一次
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
      console.warn('自动 pull 群消息失败:', exc);
    }
    // pull 失败时仍透传原始通知
    await this._dispatcher.publish('group.message_created', notification);
  }

  /** 后台补齐群消息空洞 */
  private async _fillGroupGap(groupId: string): Promise<void> {
    // 状态保护：非 connected 或正在关闭时跳过（与 Python 对齐）
    if (this._state !== 'connected' || this._closing) return;
    const ns = `group:${groupId}`;
    const afterSeq = this._seqTracker.getContiguousSeq(ns);
    // 冷启动（seq=0）：服务端推送会带全量消息，SDK 不主动补洞避免重复拉取
    if (afterSeq === 0) {
      return;
    }
    // 去重：同一 (group:id:after_seq) 在飞行中只补一次
    // S1: 使用 try/finally 保证无论成功失败都清理 dedupKey，避免旧实现只在异常路径清理
    // 导致成功后相同 afterSeq 再次出现空洞时被永久抑制。
    const dedupKey = `group_msg:${groupId}:${afterSeq}`;
    if (this._gapFillDone.has(dedupKey)) return;
    this._gapFillDone.add(dedupKey);
    this._gapFillActive = true;
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
          // ⚠️ 不再重复调用 onPullResult：call('group.pull') 拦截器已在内部调用过一次
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
    } catch (exc) {
      console.warn('[aun_core] 群消息补洞失败:', exc);
    } finally {
      // S1: 成功 / 失败路径都必须清理飞行标记
      this._gapFillDone.delete(dedupKey);
      this._gapFillActive = false;
    }
  }

  /** 后台补齐群事件空洞 */
  private async _fillGroupEventGap(groupId: string): Promise<void> {
    // 状态保护：非 connected 或正在关闭时跳过（与 Python 对齐）
    if (this._state !== 'connected' || this._closing) return;
    const ns = `group_event:${groupId}`;
    const afterSeq = this._seqTracker.getContiguousSeq(ns);
    // 冷启动（seq=0）：服务端推送会带全量事件，SDK 不主动补洞避免重复拉取
    if (afterSeq === 0) {
      return;
    }
    // 去重：同一 (group_evt:id:after_seq) 在飞行中只补一次
    // S1: 使用 try/finally 保证无论成功失败都清理 dedupKey
    const dedupKey = `group_evt:${groupId}:${afterSeq}`;
    if (this._gapFillDone.has(dedupKey)) return;
    this._gapFillDone.add(dedupKey);
    this._gapFillActive = true;
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
            }).catch((e) => { console.warn('群事件 auto-ack 失败: group=' + groupId, e); });
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
    } catch (exc) {
      console.warn('[aun_core] 群事件补洞失败:', exc);
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
    // 新设备（seq=0）没有历史 prekey，拉旧消息也解不了
    if (afterSeq === 0) {
      return;
    }
    // 去重：同一 (type:after_seq) 在飞行中只补一次
    // S1: 使用 try/finally 保证无论成功失败都清理 dedupKey
    const dedupKey = `p2p:${afterSeq}`;
    if (this._gapFillDone.has(dedupKey)) return;
    this._gapFillDone.add(dedupKey);
    this._gapFillActive = true;
    try {
      const result = await this.call('message.pull', {
        after_seq: afterSeq,
        limit: 50,
      });
      if (isJsonObject(result)) {
        const messages = result.messages;
        if (Array.isArray(messages)) {
          // ⚠️ 不再重复调用 onPullResult：call('message.pull') 拦截器已在内部调用过一次
          // 与 _fillGroupGap 路径对齐，避免双重 tracker 推进。
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
    } catch (exc) {
      console.warn('[aun_core] P2P 消息补洞失败:', exc);
    } finally {
      // S1: 成功 / 失败路径都必须清理飞行标记
      this._gapFillDone.delete(dedupKey);
      this._gapFillActive = false;
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

  /**
   * 上线/重连后一次性同步所有已加入群：
   * 1. 有 epoch key 的群 → 补消息 + 补事件
   * 2. 无 epoch key 的群 → 主动向 owner 请求密钥恢复 + 补事件
   */
  private async _syncAllGroupsOnce(): Promise<void> {
    try {
      const result = await this.call('group.list_my', {});
      if (!isJsonObject(result)) return;
      const items = result.items;
      if (!Array.isArray(items)) return;
      for (const g of items) {
        if (isJsonObject(g)) {
          const gid = (g.group_id ?? '') as string;
          if (gid) {
            const hasSecret = await this._groupE2ee.hasSecret(gid);
            if (!hasSecret) {
              // 没有 epoch key → 主动向 owner 请求密钥恢复（与 Python 对齐）
              const ownerAid = (g.owner_aid ?? '') as string;
              if (ownerAid && ownerAid !== this._aid) {
                await this._requestGroupKeyFrom(gid, ownerAid);
              } else {
                console.debug(`[aun_core] 群 ${gid} 无 epoch key 且无法确定 owner，等待推送触发恢复`);
              }
            } else {
              // 有 epoch key → 补消息
              await this._fillGroupGap(gid);
            }
            // 所有群都补事件（事件不加密）
            await this._fillGroupEventGap(gid);
          }
        }
      }
    } catch (exc) {
      console.warn('[aun_core] 上线群组同步失败，群消息可能不完整:', exc);
      this._dispatcher.publish('group.sync_failed', {
        error: exc instanceof Error ? exc.message : String(exc),
      }).catch(() => {});
    }
  }

  /** 主动向指定成员请求群组密钥（用于重连时无 epoch key 的群）（与 Python 对齐） */
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
      console.info(`[aun_core] 已向 ${targetAid} 请求群 ${groupId} 的密钥`);
    } catch (exc) {
      console.warn(`[aun_core] 向 ${targetAid} 请求群 ${groupId} 密钥失败:`, exc);
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
      // 验签：有 client_signature 就验，没有默认安全
      const cs = d.client_signature;
      if (cs && isJsonObject(cs)) {
        d._verified = await this._verifyEventSignature(d, cs);
      }
      await this._dispatcher.publish('group.changed', d);

      const groupId = (d.group_id ?? '') as string;

      // event_seq 空洞检测：持久化后的 group.changed 会携带 event_seq。
      // 用 onMessageSeq 返回值决定是否补拉，与 P2P / group.message 路径对齐。
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

      if (d.action === 'member_left' || d.action === 'member_removed') {
        if (groupId) {
          const expectedEpoch = this._membershipRotationExpectedEpoch(d);
          if (expectedEpoch === null) {
            console.debug('membership event without old_epoch skipped for epoch rotation: aid=%s group=%s action=%s event_seq=%s', this._aid ?? '', groupId, String(d.action ?? ''), String(d.event_seq ?? ''));
          } else {
            this._safeAsync(this._maybeLeadRotateGroupEpoch(groupId, this._membershipRotationTriggerId(groupId, d), expectedEpoch));
          }
        }
      }

      if (['member_added', 'joined', 'join_approved', 'invite_code_used'].includes(String(d.action ?? ''))) {
        if (groupId) {
          const expectedEpoch = this._membershipRotationExpectedEpoch(d);
          if (expectedEpoch === null) {
            console.debug('membership event without old_epoch skipped for epoch rotation: aid=%s group=%s action=%s event_seq=%s', this._aid ?? '', groupId, String(d.action ?? ''), String(d.event_seq ?? ''));
          } else {
            this._safeAsync(this._maybeLeadRotateGroupEpoch(groupId, this._membershipRotationTriggerId(groupId, d), expectedEpoch));
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
   * 群组解散后清理本地状态：
   * - keystore 中的 epoch key 数据
   * - seq_tracker 中的群消息和群事件 seq 记录
   * - 补洞去重缓存中的相关条目
   * - 推送 seq 去重缓存
   */
  private _cleanupDissolvedGroup(groupId: string): void {
    // 1. 清理 GroupE2EEManager / keystore 中的 epoch 密钥
    this._safeAsync(
      this._groupE2ee.removeGroup(groupId).catch((exc: unknown) => {
        console.warn(`[aun_core] 清理解散群组 ${groupId} epoch 密钥失败:`, exc);
      }),
    );

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

    console.info(`[aun_core] 已清理解散群组 ${groupId} 的本地状态`);
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
          console.warn('[aun_core] 群事件验签失败：证书指纹不匹配 aid=%s', sigAid);
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
        console.warn('[aun_core] 群事件验签失败 aid=%s method=%s', sigAid, method);
      }
      return ok;
    } catch (exc) {
      console.warn('[aun_core] 群事件验签异常:', exc);
      return false;
    }
  }

  // ── E2EE 自动加密 ────────────────────────────────

  /** 自动加密并发送 P2P 消息 */
  private async _sendEncrypted(params: RpcParams): Promise<RpcResult> {
    const toAid = String(params.to ?? '');
    this._validateMessageRecipient(toAid);
    const payload = isJsonObject(params.payload) ? params.payload : null;
    const messageId = String(params.message_id ?? '') || _uuidV4();
    const timestamp = (params.timestamp as number) ?? Date.now();
    if (payload === null) {
      throw new ValidationError('message.send payload must be an object when encrypt=true');
    }
    const persistRequired = Boolean(params.persist_required || params.durable);

    // Lazy P2P sync：首次发送前自动拉取历史，避免重连后 seq 空洞
    if (!this._p2pSynced) {
      await this._lazySyncP2p();
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
        persistRequired,
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
    if (persistRequired) {
      sendParams.persist_required = true;
    }
    return this._transport.call('message.send', sendParams);
  }

  /**
   * 首次发送 P2P 消息前懒拉取历史消息，同步 seqTracker 避免空洞。
   * 只在本连接周期内执行一次。
   */
  private async _lazySyncP2p(): Promise<void> {
    this._p2pSynced = true;
    if (!this._aid) return;
    const ns = `p2p:${this._aid}`;
    const afterSeq = this._seqTracker.getContiguousSeq(ns);
    try {
      const result = await this._transport.call('message.pull', {
        after_seq: afterSeq,
        limit: 200,
      });
      if (isJsonObject(result)) {
        const messages = result.messages;
        if (Array.isArray(messages) && messages.length > 0) {
          this._seqTracker.onPullResult(ns, messages.filter(isJsonObject));
          this._saveSeqTrackerState();
        }
      }
    } catch (exc) {
      console.warn('[aun_core] lazySyncP2p 失败:', exc);
    }
  }

  private async _sendEncryptedSingle(opts: {
    toAid: string;
    payload: JsonObject;
    messageId: string;
    timestamp: number;
    prekey?: PrekeyMaterial | null;
    persistRequired?: boolean;
  }): Promise<RpcResult> {
    let prekey = opts.prekey;
    if (prekey === undefined) {
      prekey = await this._fetchPeerPrekey(opts.toAid);
    }
    const peerCertFingerprint = typeof prekey?.cert_fingerprint === 'string' ? prekey.cert_fingerprint : undefined;
    const peerCertPem = await this._fetchPeerCert(opts.toAid, peerCertFingerprint);
    const [envelope, encryptResult] = await this._encryptCopyPayload({
      logicalToAid: opts.toAid,
      payload: opts.payload,
      peerCertPem,
      prekey,
      messageId: opts.messageId,
      timestamp: opts.timestamp,
    });
    await this._ensureEncryptResult(opts.toAid, encryptResult);
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
    return this._transport.call('message.send', sendParams);
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
      const [envelope, encryptResult] = await this._encryptCopyPayload({
        logicalToAid: opts.toAid,
        payload: opts.payload,
        peerCertPem,
        prekey,
        messageId: opts.messageId,
        timestamp: opts.timestamp,
      });
      await this._ensureEncryptResult(opts.toAid, encryptResult);
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
    const normalized = String(certFingerprint ?? '').trim().toLowerCase();
    const identityCert = typeof this._identity?.cert === 'string' ? this._identity.cert : '';
    if (identityCert) {
      const actual = await this._certFingerprint(identityCert);
      if (!normalized || actual === normalized) {
        return identityCert;
      }
    }
    const localCert = await this._keystore.loadCert(myAid, normalized || undefined);
    if (localCert) {
      if (!normalized) {
        return localCert;
      }
      const actualFingerprint = await this._certFingerprint(localCert);
      if (actualFingerprint === normalized) {
        return localCert;
      }
    }
    return await this._fetchPeerCert(myAid, normalized || undefined);
  }

  private async _buildSelfSyncCopies(opts: {
    logicalToAid: string;
    payload: JsonObject;
    messageId: string;
    timestamp: number;
  }): Promise<JsonObject[]> {
    const myAid = this._aid;
    if (!myAid) return [];
    const prekeys = await this._fetchPeerPrekeys(myAid);
    if (prekeys.length === 0) return [];
    const copies: JsonObject[] = [];
    for (const prekey of prekeys) {
      const deviceId = String((prekey as JsonObject).device_id ?? '').trim();
      if (deviceId && deviceId === this._deviceId) {
        continue;
      }
      const peerCertPem = await this._resolveSelfCopyPeerCert(
        String(prekey.cert_fingerprint ?? '').trim().toLowerCase() || undefined,
      );
      const [envelope, encryptResult] = await this._encryptCopyPayload({
        logicalToAid: opts.logicalToAid,
        payload: opts.payload,
        peerCertPem,
        prekey,
        messageId: opts.messageId,
        timestamp: opts.timestamp,
      });
      await this._ensureEncryptResult(myAid, encryptResult);
      copies.push({
        device_id: deviceId,
        envelope,
      });
    }
    return copies;
  }

  private async _encryptCopyPayload(opts: {
    logicalToAid: string;
    payload: JsonObject;
    peerCertPem: string;
    prekey?: PrekeyMaterial | null;
    messageId: string;
    timestamp: number;
  }): Promise<[JsonObject, JsonObject]> {
    const [envelope, encryptResult] = await this._e2ee.encryptOutbound(
      opts.logicalToAid,
      opts.payload,
      {
        peerCertPem: opts.peerCertPem,
        prekey: opts.prekey ?? null,
        messageId: opts.messageId,
        timestamp: opts.timestamp,
      },
    );
    return [envelope, encryptResult as unknown as JsonObject];
  }

  private async _ensureEncryptResult(toAid: string, encryptResult: JsonObject): Promise<void> {
    if (!encryptResult.encrypted) {
      throw new E2EEError(`failed to encrypt message to ${toAid}`);
    }
    if (this.configModel.requireForwardSecrecy && !encryptResult.forward_secrecy) {
      throw new E2EEError(`forward secrecy required but unavailable for ${toAid} (mode=${encryptResult.mode})`);
    }
    if (encryptResult.degraded) {
      try {
        await this._dispatcher.publish('e2ee.degraded', {
          peer_aid: toAid,
          mode: encryptResult.mode,
          reason: encryptResult.degradation_reason,
        });
      } catch (exc) {
        console.warn('发布 e2ee.degraded 事件失败:', exc);
      }
    }
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

    // Lazy group sync：首次发送群消息前自动拉取历史，避免重连后 seq 空洞
    if (!this._groupSynced.has(groupId)) {
      await this._lazySyncGroup(groupId);
    }

    await this._ensureGroupEpochReady(groupId, false);
    await this._waitForGroupMembershipEpochFloor(groupId, 2000);

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const epochResult = await this._committedGroupEpochState(groupId);
      const committedEpoch = Number(epochResult.committed_epoch ?? epochResult.epoch ?? 0);
      const envelope = committedEpoch > 0
        ? await this._groupE2ee.encryptWithEpoch(
          groupId,
          await this._ensureCommittedGroupSecretForSend(groupId, committedEpoch, epochResult),
          payload,
        )
        : await this._groupE2ee.encrypt(groupId, payload);
      const sendParams: RpcParams = {
        group_id: groupId,
        payload: envelope,
        type: 'e2ee.group_encrypted',
        encrypted: true,
      };
      if (this._deviceId && sendParams.device_id === undefined) {
        sendParams.device_id = this._deviceId;
      }
      await this._signClientOperation('group.send', sendParams);
      try {
        return await this._transport.call('group.send', sendParams);
      } catch (exc) {
        if (attempt === 0 && this._isRecoverableGroupEpochError(exc)) {
          console.warn(`[aun_core] 群 ${groupId} 发送时 epoch 已过旧，恢复密钥后重加密重发一次: ${formatCaughtError(exc)}`);
          await this._ensureGroupEpochReady(groupId, true);
          continue;
        }
        throw exc;
      }
    }
    throw new StateError(`group ${groupId} send failed after epoch recovery retry`);
  }

  /**
   * 首次发送群消息前懒拉取历史消息，同步 seqTracker 避免空洞。
   * 只在本连接周期内执行一次（per groupId）。
   */
  private async _lazySyncGroup(groupId: string): Promise<void> {
    this._groupSynced.add(groupId);
    const ns = `group:${groupId}`;
    const afterSeq = this._seqTracker.getContiguousSeq(ns);
    try {
      const result = await this._transport.call('group.pull', {
        group_id: groupId,
        after_message_seq: afterSeq,
        device_id: this._deviceId,
        limit: 200,
      });
      if (isJsonObject(result)) {
        const messages = result.messages;
        if (Array.isArray(messages) && messages.length > 0) {
          this._seqTracker.onPullResult(ns, messages.filter(isJsonObject));
          this._saveSeqTrackerState();
        }
      }
    } catch (exc) {
      console.warn(`[aun_core] lazySyncGroup(${groupId}) 失败:`, exc);
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

  private async _groupKeyRecoveryCandidates(groupId: string, epochResult: JsonObject): Promise<string[]> {
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
    const localMembers = await this._groupE2ee.getMemberAids(groupId);
    for (const aid of localMembers) add(aid);
    return candidates;
  }

  private async _requestGroupKeyFromCandidates(groupId: string, serverEpoch: number, epochResult: JsonObject): Promise<void> {
    for (const targetAid of await this._groupKeyRecoveryCandidates(groupId, epochResult)) {
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
    const secretData = await this._groupE2ee.loadSecret(groupId, 1) as JsonObject | null;
    if (!secretData || secretData.pending_rotation_id) return epochResult;
    console.warn(`[aun_core] 群 ${groupId} 检测到本地 epoch 1 已存在但服务端 epoch 仍为 0，尝试补同步初始 epoch`);
    await this._syncEpochToServer(groupId);
    try {
      const refreshed = await this.call('group.e2ee.get_epoch', { group_id: groupId });
      if (isJsonObject(refreshed)) return refreshed;
    } catch (exc) {
      console.warn(`[aun_core] 群 ${groupId} 初始 epoch 补同步后刷新服务端 epoch 失败: ${formatCaughtError(exc)}`);
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
      console.warn(`[aun_core] group ${groupId} epoch precheck failed: ${formatCaughtError(exc)}`);
      return;
    }
    let serverEpoch = Number(epochResult.epoch ?? 0);
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
      serverEpoch = Number(epochResult.epoch ?? 0);
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
        const refreshedEpoch = isJsonObject(refreshed) ? Number(refreshed.epoch ?? 0) : 0;
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

    console.warn(`[aun_core] group ${groupId} local epoch=${effectiveLocalEpoch} < server epoch=${serverEpoch}; requesting key recovery`);
    await this._requestGroupKeyFromCandidates(groupId, serverEpoch, epochResult);

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
        console.warn(`[aun_core] 群 ${groupId} 成员 epoch floor 预检跳过: ${formatCaughtError(exc)}`);
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
      console.warn(`[aun_core] 群 ${groupId} 成员 min_read_epoch 高于 committed epoch，按 committed epoch 继续发送: committed=${committedEpoch} floor=${maxMinReadEpoch}`);
      return;
    }
  }

  private async _committedGroupEpochState(groupId: string): Promise<JsonObject> {
    try {
      const epochResult = await this.call('group.e2ee.get_epoch', { group_id: groupId });
      if (isJsonObject(epochResult)) return epochResult;
    } catch (exc) {
      console.warn(`[aun_core] 群 ${groupId} 查询 committed epoch 状态失败，回退本地 epoch: ${formatCaughtError(exc)}`);
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
    const secretData = await this._groupE2ee.loadSecret(groupId, committedEpoch) as JsonObject | null;
    const committedRotation = isJsonObject(epochResult.committed_rotation) ? epochResult.committed_rotation : null;
    if (this._groupSecretMatchesCommittedRotation(secretData, committedRotation)) {
      return committedEpoch;
    }
    const pendingRotationId = secretData ? String(secretData.pending_rotation_id ?? '') : '';
    console.warn(`[aun_core] 群 ${groupId} epoch ${committedEpoch} 本地 pending key 未匹配服务端 committed rotation，先恢复密钥: local_rotation=${pendingRotationId || '-'}`);
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

  // ── E2EE 自动解密 ────────────────────────────────

  /** 解密单条 P2P 消息 */
  private async _decryptSingleMessage(message: Message): Promise<Message> {
    const payload = isJsonObject(message.payload) ? message.payload : null;
    if (payload === null) return message;
    if (payload.type !== 'e2ee.encrypted') return message;
    if (message.encrypted === false) return message;

    // 确保发送方证书已缓存（签名验证需要）
    const fromAid = (message.from ?? '') as string;
    const senderCertFingerprint = String(
      payload.sender_cert_fingerprint ?? (payload.aad as JsonObject | undefined)?.sender_cert_fingerprint ?? '',
    ).trim().toLowerCase();
    if (fromAid) {
      const certReady = await this._ensureSenderCertCached(fromAid, senderCertFingerprint || undefined);
      if (!certReady) {
        console.warn(`无法获取发送方 ${fromAid} 的证书，跳过解密`);
        throw new Error(`发送方证书不可用: from=${fromAid}, mid=${message.message_id}`);
      }
    }

    // 密码学解密（E2EEManager.decryptMessage 内含本地防重放）
    const decrypted = await this._e2ee.decryptMessage(message);
    this._schedulePrekeyReplenishIfConsumed(decrypted);
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
      const mid = (msg.message_id ?? '') as string;
      if (mid && seenInBatch.has(mid)) continue;
      if (mid) seenInBatch.add(mid);

      const payload = isJsonObject(msg.payload) ? msg.payload : null;
      if (payload !== null && await this._tryHandleGroupKeyMessage(msg)) {
        continue;
      }
      if (payload !== null
        && payload.type === 'e2ee.encrypted'
        && (msg.encrypted === true || !('encrypted' in msg))) {
        const fromAid = (msg.from ?? '') as string;
        const senderCertFingerprint = String(
          payload.sender_cert_fingerprint ?? (payload.aad as JsonObject | undefined)?.sender_cert_fingerprint ?? '',
        ).trim().toLowerCase();
        if (fromAid) {
          const certReady = await this._ensureSenderCertCached(fromAid, senderCertFingerprint || undefined);
          if (!certReady) {
            console.warn(`无法获取发送方 ${fromAid} 的证书，跳过解密`);
            continue;
          }
        }
        // Pull 场景：跳过防重放和 timestamp 窗口检查（push 已处理过的消息仍需要能解密）
        const decrypted = await this._e2ee.decryptMessage(msg, { skipReplay: true });
        if (decrypted !== null) {
          result.push(decrypted);
        }
      } else {
        result.push(msg);
      }
    }
    return result;
  }

  /** 解密单条群组消息。opts.skipReplay 用于 pull 场景跳过防重放。 */
  private _enqueuePendingDecrypt(groupId: string, msg: Message): void {
    const ns = `group:${groupId}`;
    const queue = this._pendingDecryptMsgs.get(ns) ?? [];
    queue.push(msg as JsonObject);
    this._pendingDecryptMsgs.set(ns, queue.slice(-200));
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
        await this._dispatcher.publish('group.message_created', decrypted);
      } catch {
        stillPending.push(msg);
      }
    }
    const queuedDuringRetry = this._pendingDecryptMsgs.get(ns) ?? [];
    const mergedPending = [...stillPending, ...queuedDuringRetry].slice(-200);
    if (mergedPending.length) this._pendingDecryptMsgs.set(ns, mergedPending);
    else this._pendingDecryptMsgs.delete(ns);
  }

  private _scheduleRetryPendingDecryptMsgs(groupId: string): void {
    if (!groupId || !this._pendingDecryptMsgs.has(`group:${groupId}`)) return;
    this._safeAsync(this._retryPendingDecryptMsgs(groupId));
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

  private async _doRecoverGroupEpochKey(groupId: string, epoch: number, senderAid: string, timeoutMs: number): Promise<boolean> {
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
    await this._requestGroupKeyFromCandidates(groupId, epoch, epochResult);
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
    const payload = isJsonObject(message.payload) ? message.payload : null;
    if (payload === null || payload.type !== 'e2ee.group_encrypted') {
      return message;
    }

    // 确保发送方证书已缓存（签名验证需要）
    const senderAid = String(message.from ?? message.sender_aid ?? '');
    if (senderAid) {
      const certOk = await this._ensureSenderCertCached(senderAid);
      if (!certOk) {
        console.warn(`群消息解密跳过：发送方 ${senderAid} 证书不可用`);
        return message;
      }
    }

    // 先尝试直接解密
    const result = await this._groupE2ee.decrypt(message, opts);
    if (result !== null && isJsonObject(result.e2ee)) {
      return result;
    }

    // replay guard 命中：decrypt 返回了原消息（非 null）但无 e2ee 字段
    // 不是解密失败，不应触发 recover
    if (result !== null) {
      return result;
    }

    // 真正的解密失败（result === null），尝试密钥恢复后重试
    const groupId = String(message.group_id ?? '');
    const sender = String(message.from ?? message.sender_aid ?? '');
    const epoch = Number(payload.epoch ?? 0);
    if (epoch > 0 && groupId) {
      try {
        if (await this._recoverGroupEpochKey(groupId, epoch, sender, 5000)) {
          const retry = await this._groupE2ee.decrypt(message, opts);
          if (retry !== null && retry.e2ee) return retry;
        }
      } catch (exc) {
        console.debug(`[aun_core] 群 ${groupId} epoch ${epoch} 同步恢复失败: ${formatCaughtError(exc)}`);
      }
    }

    return message;
  }

  /** 批量解密群组消息（用于 group.pull）。跳过防重放检查。 */
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
      result.push(decrypted);
    }
    return result;
  }

  /**
   * 尝试处理 P2P 传输的群组密钥消息。
   *
   * 返回值：
   *   - true  = 已处理 / 已被抑制（外层不应再 publish 到业务事件）
   *   - false = 非密钥消息，外层应继续走普通 P2P 消息链路
   *
   * 外层 payload.type === 'e2ee.encrypted' 需要先解密才能判定是否为控制面。
   * 解密失败交给普通链路处理；普通链路只发布安全的 undecryptable 事件。
   */
  private async _tryHandleGroupKeyMessage(message: Message): Promise<boolean> {
    let actualPayload = isJsonObject(message.payload) ? message.payload : null;
    if (actualPayload === null) return false;

    // 先解密 P2P E2EE 外壳
    if (actualPayload.type === 'e2ee.encrypted') {
      const fromAid = (message.from ?? '') as string;
      const senderCertFingerprint = String(
        actualPayload.sender_cert_fingerprint ?? (actualPayload.aad as JsonObject | undefined)?.sender_cert_fingerprint ?? '',
      ).trim().toLowerCase();
      if (fromAid) {
        await this._ensureSenderCertCached(fromAid, senderCertFingerprint || undefined);
      }
      let decrypted: Message | null = null;
      try {
        decrypted = await this._e2ee.decryptMessage(message, { skipReplay: true });
      } catch (exc) {
        console.warn('[aun_core] e2ee.encrypted 外壳解密抛异常，交给普通链路处理:', exc);
        return false;
      }
      if (!decrypted) {
        return false;
      }
      this._schedulePrekeyReplenishIfConsumed(decrypted);
      actualPayload = isJsonObject(decrypted.payload) ? decrypted.payload : null;
      if (actualPayload === null) return false;
    }

    // S14: 按 envelope_type 识别控制面消息。内层 type 以 'e2ee.group_key_' 开头的
    //      一律视为群组密钥控制面，无论 handleIncoming 成功还是被拒绝，都不应
    //      向业务层投递。
    const innerType = String(actualPayload.type ?? '');
    const isGroupKeyCtrl = innerType.startsWith('e2ee.group_key_');

    let result: string | null = null;
    try {
      if (actualPayload.type === 'e2ee.group_key_distribution') {
        if (!await this._verifyActiveGroupRotationDistribution(actualPayload)) {
          return true;
        }
      } else if (actualPayload.type === 'e2ee.group_key_response') {
        if (!await this._verifyGroupKeyResponseEpoch(actualPayload)) {
          return true;
        }
      }
      result = await this._groupE2ee.handleIncoming(actualPayload);
      if (result === 'distribution') {
        await this._discardGroupDistributionIfStale(actualPayload);
      }
    } catch (exc) {
      console.warn('[aun_core] 群组密钥消息处理异常:', exc);
      // S14: 控制面消息处理异常也要抑制业务分发
      if (isGroupKeyCtrl) return true;
      return false;
    }
    if (result === null) {
      // 非密钥消息。但若 envelope_type 显示为控制面（防御性：handleIncoming
      // 未识别但类型前缀匹配），仍抑制业务分发。
      return isGroupKeyCtrl;
    }

    if (result === 'request') {
      // 处理密钥请求并回复
      const groupId = (actualPayload.group_id ?? '') as string;
      const requester = (actualPayload.requester_aid ?? '') as string;
      let members = await this._groupE2ee.getMemberAids(groupId);

      // 请求者不在本地成员列表时，回源查询服务端最新成员列表
      if (requester && !members.includes(requester)) {
        try {
          const membersResult = await this.call('group.get_members', { group_id: groupId });
          const memberList = isJsonObject(membersResult) && Array.isArray(membersResult.members)
            ? membersResult.members as MemberRecord[]
            : [];
          members = memberList.map(m => String(m.aid ?? ''));
          // 更新本地当前 epoch 的 member_aids/commitment
          if (members.includes(requester)) {
            const secretData = await this._groupE2ee.loadSecret(groupId);
            if (secretData && this._aid) {
              const epoch = secretData.epoch;
              const commitment = await computeMembershipCommitment(members, epoch, groupId, secretData.secret);
              await storeGroupSecret(
                this._keystore, this._aid, groupId, epoch,
                secretData.secret, commitment, members,
              );
            }
          }
        } catch (exc) {
          console.warn(`群组 ${groupId} 成员列表回源失败:`, exc);
        }
      }

      const response = await this._groupE2ee.handleKeyRequestMsg(actualPayload, members);
      if (response && requester) {
        try {
          await this.call('message.send', {
            to: requester,
            payload: response,
            encrypt: true,
            persist_required: true,
          });
        } catch (exc) {
          console.warn(`向 ${requester} 回复群组密钥失败:`, exc);
        }
      }
    }

    // R4: 收到 distribution/response 后触发 pending 消息重试
    if (result === 'distribution' || result === 'response') {
      const groupId = String(actualPayload.group_id ?? '');
      const rotationId = String(actualPayload.rotation_id ?? '');
      const keyCommitment = String(actualPayload.commitment ?? '');
      if (rotationId && keyCommitment) {
        this._safeAsync(this._ackGroupRotationKey(rotationId, keyCommitment).then(() => undefined));
      }
      this._scheduleRetryPendingDecryptMsgs(groupId);
    }

    return true;
  }

  // ── E2EE 编排：证书与 prekey ──────────────────────

  /**
   * 获取对方证书（带缓存 + 完整 PKI 验证：链 + CRL + OCSP + AID 绑定）。
   * 跨域时自动将请求路由到 peer 所在域的 Gateway。
   */
  private async _fetchPeerCert(aid: string, certFingerprint?: string): Promise<string> {
    const cacheKey = certCacheKey(aid, certFingerprint);
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
    const peerGatewayUrl = resolvePeerGatewayUrl(gatewayUrl, aid);
    let certPem: string;
    try {
      const certUrl = buildCertUrl(peerGatewayUrl, aid, certFingerprint);
      // 兼容旧浏览器，不使用 AbortSignal.timeout（Chrome 103+ 才支持）
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
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
      const fallbackTimeoutId = setTimeout(() => fallbackController.abort(), 5000);
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
      console.error(`写入证书到 keystore 失败 (aid=${aid}):`, exc);
    }

    return certPem;
  }

  /** 获取对方所有设备的 prekey（带缓存）。 */
  private async _fetchPeerPrekeys(peerAid: string): Promise<PrekeyMaterial[]> {
    const cachedList = this._peerPrekeysCache.get(peerAid);
    if (cachedList && Date.now() / 1000 < cachedList.expireAt) {
      return cachedList.items.map((item) => ({ ...item }));
    }
    const cached = this._e2ee.getCachedPrekey(peerAid);
    if (cached !== null && isPeerPrekeyMaterial(cached)) {
      return [{ ...cached }];
    }
    let result: RpcResult;
    try {
      result = await this._transport.call('message.e2ee.get_prekey', { aid: peerAid });
    } catch (exc) {
      throw new ValidationError(`failed to fetch peer prekey for ${peerAid}: ${String(exc)}`);
    }
    if (!isJsonObject(result)) {
      throw new ValidationError(`invalid prekey response for ${peerAid}`);
    }
    if (result.found === false) {
      return [];
    }
    const devicePrekeys = Array.isArray(result.device_prekeys) ? result.device_prekeys : null;
    if (devicePrekeys) {
      const normalized = devicePrekeys.filter(isPeerPrekeyMaterial).map((item) => ({ ...item }));
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
    if (result.prekey) {
      this._peerPrekeysCache.set(peerAid, {
        items: [{ ...result.prekey }],
        expireAt: Date.now() / 1000 + 300,
      });
      this._e2ee.cachePrekey(peerAid, result.prekey);
      return [{ ...result.prekey }];
    }
    if (result.found) {
      throw new ValidationError(`invalid prekey response for ${peerAid}`);
    }
    return [];
  }

  /** 获取对方 prekey（兼容接口，优先返回第一条 device prekey）。 */
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
    const prekeyMaterial = await this._e2ee.generatePrekey();
    const result = await this._transport.call('message.e2ee.put_prekey', prekeyMaterial);
    return isJsonObject(result) ? { ...result } : { ok: true };
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
        console.warn(`刷新发送方 ${aid} 证书失败，继续使用已验证的内存缓存:`, exc);
        return true;
      }
      console.warn(`获取发送方 ${aid} 证书失败且无已验证缓存，拒绝信任:`, exc);
      return false;
    }
  }

  /**
   * 获取经过 PKI 验证的 peer 证书（仅信任内存缓存中已验证的证书）。
   * 零信任要求：不直接信任 keystore 中可能由恶意服务端注入的证书。
   */
  private _getVerifiedPeerCert(aid: string, certFingerprint?: string): string | null {
    const cached = this._certCache.get(certCacheKey(aid, certFingerprint));
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
    const identity = this._identity;
    if (!identity || !identity.private_key_pem) return;

    try {
      const aid = (identity.aid ?? '') as string;
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
      const pkcs8 = pemToArrayBuffer(identity.private_key_pem as string);
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
      const certPem = (identity.cert ?? '') as string;
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

  // ── E2EE 编排：Group 生命周期 ─────────────────────

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
            await this._sleep((attempt + 1) * 1000);
          } else {
            failed.push(String(dist.to));
            console.warn('epoch 密钥分发失败 (to=%s):', dist.to, exc);
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
      console.warn(`[aun_core] 刷新 epoch rotation lease 失败: rotation=${rotationId} err=${formatCaughtError(exc)}`);
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
      console.warn(`[aun_core] 提交 epoch key ack 失败: rotation=${rotationId} err=${formatCaughtError(exc)}`);
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
            if (committedCommitment && commitment && committedCommitment !== commitment) return false;
          }
          return true;
        }
        console.info(`[aun_core] 拒绝缺少 rotation_id 的未来 epoch key 分发: group=${groupId} epoch=${epoch} committed=${committedEpoch}`);
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
      console.warn(`[aun_core] 拒绝无法校验 active rotation 的 epoch key 分发: group=${groupId} rotation=${rotationId} err=${formatCaughtError(exc)}`);
      return false;
    }
    console.info(`[aun_core] 拒绝非 pending/committed 状态的 epoch key 分发: group=${groupId} rotation=${rotationId} epoch=${epoch}`);
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
      await this._groupE2ee.discardPendingSecret(groupId, epoch, rotationId);
      console.info('丢弃 verify 后变为 stale 的 group epoch key: group=%s epoch=%s rotation=%s',
        groupId, epoch, rotationId);
    } catch (exc) {
      console.debug('清理 stale group epoch key 失败: group=%s epoch=%s rotation=%s err=%s',
        groupId, epoch, rotationId, formatCaughtError(exc));
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
        console.info(`[aun_core] 拒绝未提交 epoch 的 group key response: group=${groupId} epoch=${epoch} committed=${committedEpoch}`);
        return false;
      }
      const committedRotation = isJsonObject(epochResult.committed_rotation) ? epochResult.committed_rotation : null;
      if (committedRotation && Number(committedRotation.target_epoch ?? committedEpoch) === epoch) {
        const committedCommitment = String(committedRotation.key_commitment ?? '').trim();
        if (committedCommitment && commitment && committedCommitment !== commitment) return false;
      }
      return true;
    } catch (exc) {
      console.warn(`[aun_core] 拒绝无法校验 committed epoch 的 group key response: group=${groupId} epoch=${epoch} err=${formatCaughtError(exc)}`);
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
      console.warn(`[aun_core] 中止 epoch rotation 失败: rotation=${rotationId} err=${formatCaughtError(exc)}`);
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
      this._safeAsync(this._maybeLeadRotateGroupEpoch(groupId, opts.triggerId, opts.expectedEpoch));
    }, this._rotationRetryDelayMs(opts.pending));
    this._groupEpochRotationRetryTimers.set(retryKey, timer);
  }

  /** 建群后将本地 epoch 1 同步到服务端，最多重试 3 次 */
  private async _syncEpochToServer(groupId: string): Promise<void> {
    const started = Date.now();
    while (this._groupEpochRotationInflight.has(groupId)) {
      if (this._closing || this._state !== 'connected') return;
      if (Date.now() - started > 20000) {
        console.warn('group epoch create sync still in-flight; skip duplicate sync (group=%s)', groupId);
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
          const secretData = await this._groupE2ee.loadSecret(groupId, 1);
          if (!secretData) throw new StateError(`group ${groupId} epoch 1 secret missing`);
          const rotationId = `rot-${_uuidV4().replace(/-/g, '')}`;
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
          const sigParams = await this._buildRotationSignature(groupId, 0, 1, rotateParams);
          Object.assign(rotateParams, sigParams);
          const beginResult = await this.call('group.e2ee.begin_rotation', rotateParams);
          const rotation = isJsonObject(beginResult) && isJsonObject(beginResult.rotation) ? beginResult.rotation : null;
          if (!isJsonObject(beginResult) || beginResult.success !== true || !rotation) {
            console.warn('group epoch begin failed; stop key distribution (group=%s, returned=%s)', groupId, JSON.stringify(beginResult));
            return;
          }
          const activeRotationId = String(rotation.rotation_id ?? rotationId);
          if (!await this._ackGroupRotationKey(activeRotationId, secretData.commitment)) {
            console.warn('group epoch self ack failed (group=%s, rotation=%s)', groupId, activeRotationId);
            await this._abortGroupRotation(activeRotationId, 'self_ack_failed');
            return;
          }
          const commitResult = await this.call('group.e2ee.commit_rotation', { rotation_id: activeRotationId });
          if (isJsonObject(commitResult) && commitResult.success === true) {
            await storeGroupSecret(
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
          console.warn('group epoch commit failed (group=%s, returned=%s)', groupId, JSON.stringify(commitResult));
          return;
        } catch (exc) {
          if (attempt < maxRetries) {
            const delay = 500 * Math.pow(2, attempt - 1);
            console.warn(`同步 epoch 到服务端失败 (group=${groupId}, 第${attempt}/${maxRetries}次), ${delay}ms后重试:`, exc);
            await new Promise(r => setTimeout(r, delay));
          } else {
            console.error(`同步 epoch 到服务端最终失败 (group=${groupId}, 已重试${maxRetries}次):`, exc);
          }
        }
      }
    } finally {
      this._groupEpochRotationInflight.delete(groupId);
    }
  }

  /**
   * H21: 基于"排序最小 admin = leader"选举，其他 admin 走 jitter 兜底重试。
   * 避免所有剩余 admin 同时触发 `_rotateGroupEpoch` 造成 CAS 风暴。
   */
  private async _maybeLeadRotateGroupEpoch(groupId: string, triggerId = '', expectedEpoch: number | null = null): Promise<void> {
    const myAid = this._aid;
    if (!myAid || this._closing || this._state !== 'connected') return;
    const started = Date.now();
    while (this._groupEpochRotationInflight.has(groupId)) {
      if (triggerId && this._groupMembershipRotationDone.has(triggerId)) return;
      if (this._closing || this._state !== 'connected') return;
      if (Date.now() - started > 20000) {
        console.warn('group epoch rotation still in-flight; skip pending trigger (group=%s trigger=%s)', groupId, triggerId || '-');
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
        await this._rotateGroupEpoch(groupId, triggerId, expectedEpoch);
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
      console.info('[H21] leader 未完成 epoch 轮换，非 leader 兜底: group=%s myAid=%s', groupId, myAid);
      await this._rotateGroupEpoch(groupId, triggerId, expectedEpoch);
    } catch (exc) {
      console.warn('_maybeLeadRotateGroupEpoch 失败: %s', exc);
    } finally {
      this._groupEpochRotationInflight.delete(groupId);
    }
  }

  /**
   * 为指定群组轮换 epoch 并分发新密钥。
   * 使用服务端 CAS 保证只有一方成功。
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
          console.info('aborted stale pending group epoch rotation: group=%s rotation=%s',
            groupId, pendingRotationId || '-');
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
        console.info('skip membership epoch rotation: group=%s expected_epoch=%d server_epoch=%d trigger=%s',
          groupId, expectedEpoch, serverEpoch, triggerId || '-');
        return;
      }
      const currentEpoch = expectedEpoch ?? serverEpoch;
      const targetEpoch = currentEpoch + 1;
      const rotationId = `rot-${_uuidV4().replace(/-/g, '')}`;
      const info = await this._groupE2ee.rotateEpochTo(groupId, targetEpoch, memberAids, { rotationId });
      this._attachRotationId(info, rotationId);
      const discardGeneratedPending = async (): Promise<void> => {
        try {
          await this._groupE2ee.discardPendingSecret(groupId, targetEpoch, rotationId);
        } catch (cleanupExc) {
          console.debug('清理本地 pending group key 失败: group=%s epoch=%d rotation=%s err=%s',
            groupId, targetEpoch, rotationId, formatCaughtError(cleanupExc));
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
      const sigParams = await this._buildRotationSignature(groupId, currentEpoch, targetEpoch, rotateParams);
      Object.assign(rotateParams, sigParams);
      let rawBeginResult: any;
      try {
        rawBeginResult = await this.call('group.e2ee.begin_rotation', rotateParams);
      } catch (exc) {
        await discardGeneratedPending();
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
        console.warn('group epoch begin failed; stop key distribution (group=%s, current_epoch=%d, returned=%s)',
          groupId, currentEpoch, JSON.stringify(beginResult));
        await discardGeneratedPending();
        return;
      }

      const activeRotationId = String(rotation.rotation_id ?? rotationId);
      const distributeResult = await this._distributeGroupEpochKey(info, activeRotationId);
      if (distributeResult.failed.length > 0) {
        console.warn('group epoch key distribution incomplete; abort rotation before retry (group=%s rotation=%s failed=%s)',
          groupId, activeRotationId, distributeResult.failed.join(','));
        await this._abortGroupRotation(activeRotationId, 'distribution_failed');
        this._scheduleGroupRotationRetry(groupId, {
          reason: 'membership_changed',
          triggerId,
          expectedEpoch,
          pending: null,
        });
        await discardGeneratedPending();
        return;
      }
      await this._heartbeatGroupRotation(activeRotationId);
      if (!await this._ackGroupRotationKey(activeRotationId, String(info.commitment ?? ''))) {
        console.warn('group epoch self ack failed; abort rotation before retry (group=%s rotation=%s)', groupId, activeRotationId);
        await this._abortGroupRotation(activeRotationId, 'self_ack_failed');
        this._scheduleGroupRotationRetry(groupId, {
          reason: 'membership_changed',
          triggerId,
          expectedEpoch,
          pending: null,
        });
        await discardGeneratedPending();
        return;
      }
      const commitResult = await this.call('group.e2ee.commit_rotation', { rotation_id: activeRotationId });
      if (!isJsonObject(commitResult) || commitResult.success !== true) {
        console.warn('group epoch commit failed (group=%s, rotation=%s, returned=%s)',
          groupId, activeRotationId, JSON.stringify(commitResult));
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
          await discardGeneratedPending();
        }
        return;
      }
      const committedSecret = await this._groupE2ee.loadSecret(groupId, targetEpoch);
      if (committedSecret && this._aid) {
        const committedRotation = isJsonObject(commitResult.rotation)
          ? commitResult.rotation
          : { rotation_id: activeRotationId, key_commitment: String(info.commitment ?? '') };
        if (this._groupSecretMatchesCommittedRotation(committedSecret as unknown as JsonObject, committedRotation)) {
          await storeGroupSecret(
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
          console.warn('group epoch commit succeeded but local target key does not match committed rotation; keep pending blocked (group=%s rotation=%s epoch=%d)',
            groupId, activeRotationId, targetEpoch);
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

  /**
   * 将当前 group_secret 通过 P2P E2EE 分发给新成员。
   * 先拉服务端最新成员列表，更新本地，构建签名 manifest，再分发。
   */
  private async _distributeKeyToNewMember(groupId: string, newMemberAid: string): Promise<void> {
    try {
      const secretData = await this._groupE2ee.loadSecret(groupId);
      if (!secretData || !this._aid) return;

      // 拉服务端最新成员列表
      const membersResult = await this.call('group.get_members', { group_id: groupId });
      const memberList = isJsonObject(membersResult) && Array.isArray(membersResult.members)
        ? membersResult.members as MemberRecord[]
        : [];
      const memberAids = memberList.map(m => String(m.aid ?? ''));

      // 用最新成员列表更新本地当前 epoch
      const epoch = secretData.epoch;
      const commitment = await computeMembershipCommitment(
        memberAids, epoch, groupId, secretData.secret,
      );
      await storeGroupSecret(
        this._keystore, this._aid, groupId, epoch,
        secretData.secret, commitment, memberAids,
      );

      // 构建并签名 manifest
      let manifest = buildMembershipManifest(
        groupId, epoch, epoch, memberAids, {
          added: [newMemberAid],
          removed: [],
          initiatorAid: this._aid,
        },
      );
      const identity = this._identity;
      if (identity && identity.private_key_pem) {
        manifest = await signMembershipManifest(manifest, identity.private_key_pem as string);
      }

      const distPayload = await buildKeyDistribution(
        groupId, epoch, secretData.secret,
        memberAids, this._aid, manifest,
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
            await this._sleep((attempt + 1) * 1000);
          } else {
            throw sendExc;
          }
        }
      }
    } catch (exc) {
      this._logE2eeError('distribute_key', groupId, newMemberAid, exc as Error);
    }
  }

  /** 构建 epoch 轮换签名参数（异步，使用 SubtleCrypto）。失败时抛错，调用方在 try/catch 中跳过轮换。 */
  private async _buildRotationSignature(
    groupId: string,
    currentEpoch: number,
    newEpoch: number,
    source?: JsonObject,
  ): Promise<Record<string, string>> {
    const identity = this._identity;
    if (!identity || !identity.private_key_pem) {
      throw new StateError('rotation signature requires local identity private key');
    }

    const aid = (identity.aid ?? '') as string;
    const ts = String(Math.floor(Date.now() / 1000));
    let signData: Uint8Array;
    if (source) {
      const listField = (key: string): string[] => {
        const raw = source[key];
        return Array.isArray(raw)
          ? raw.map(item => String(item ?? '').trim()).filter(Boolean).sort()
          : [];
      };
      signData = new TextEncoder().encode(stableStringify({
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
      }));
    } else {
      signData = new TextEncoder().encode(
        `${groupId}|${currentEpoch}|${newEpoch}|${aid}|${ts}`,
      );
    }

    const pkcs8 = pemToArrayBuffer(identity.private_key_pem as string);
    const cryptoKey = await crypto.subtle.importKey(
      'pkcs8', pkcs8,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false, ['sign'],
    );
    const sigP1363 = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      cryptoKey, toBufferSource(signData),
    );

    // P1363 → DER 格式（使用顶部静态导入的 p1363ToDer）
    const sigDer = p1363ToDer(new Uint8Array(sigP1363));

    const result: Record<string, string> = {
      rotation_signature: uint8ToBase64(sigDer),
      rotation_timestamp: ts,
    };
    if (source) result.rotation_sig_version = 'v2';
    return result;
  }

  // ── 内部：连接 ────────────────────────────────────

  private async _connectOnce(params: ConnectParams, allowReauth: boolean): Promise<void> {
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
      await this._syncIdentityAfterConnect(String(params.access_token));
    }

    this._state = 'connected';
    await this._dispatcher.publish('connection.state', {
      state: this._state,
      gateway: gatewayUrl,
    });

    // auth 阶段 aid 可能被 identity 覆盖；若 context 发生变化，重新 refresh + restore。
    if (this._seqTrackerContext !== this._currentSeqTrackerContext()) {
      this._refreshSeqTrackerContext();
      await this._restoreSeqTrackerState();
    }

    this._startBackgroundTasks();

    // 上线后自动上传 prekey
    try {
      await this._uploadPrekey();
    } catch (exc) {
      console.warn('prekey 上传失败:', exc);
    }
  }

  private _resolveGateway(params: ConnectParams): string {
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
    const gateway = String(params.gateway ?? this._gatewayUrl ?? '');
    if (!gateway) throw new StateError('missing gateway in connect params');
    return gateway;
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
    return request;
  }

  private _buildSessionOptions(params: ConnectParams): SessionOptions {
    const options: SessionOptions = {
      auto_reconnect: DEFAULT_SESSION_OPTIONS.auto_reconnect,
      heartbeat_interval: DEFAULT_SESSION_OPTIONS.heartbeat_interval,
      token_refresh_before: DEFAULT_SESSION_OPTIONS.token_refresh_before,
      retry: { ...DEFAULT_SESSION_OPTIONS.retry },
      timeouts: { ...DEFAULT_SESSION_OPTIONS.timeouts },
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
    return options;
  }

  // ── 内部：后台任务 ────────────────────────────────

  private _startBackgroundTasks(): void {
    this._startHeartbeat();
    this._startTokenRefresh();
    this._startPrekeyRefresh();
    this._startGroupEpochTasks();
    // 上线/重连后一次性补齐群消息和群事件
    this._safeAsync(this._syncAllGroupsOnce());
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
    if (this._prekeyRefreshTimer !== null) {
      clearTimeout(this._prekeyRefreshTimer);
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

  /** 心跳定时器 */
  private _startHeartbeat(): void {
    if (this._heartbeatTimer !== null) return;
    const interval = this._sessionOptions.heartbeat_interval * 1000;
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
        await this._transport.call('meta.ping', {});
        consecutiveFailures = 0;
      } catch (exc) {
        consecutiveFailures++;
        console.warn(`心跳失败 (${consecutiveFailures}/${maxFailures}):`, exc);
        this._dispatcher.publish('connection.error', { error: formatCaughtError(exc) });
        if (consecutiveFailures >= maxFailures) {
          console.warn(`连续 ${maxFailures} 次心跳失败，触发断线重连`);
          this._handleTransportDisconnect(exc instanceof Error ? exc : new Error(String(exc)));
        }
      }
    }, interval);
  }

  /** Token 刷新定时器 */
  private _startTokenRefresh(): void {
    if (this._tokenRefreshTimer !== null) return;

    const scheduleRefresh = () => {
      if (this._closing) return;
      const lead = this._sessionOptions.token_refresh_before;
      const minimumDelay = 1000;

      if (this._state !== 'connected' || !this._gatewayUrl) {
        // 非连接状态下使用指数退避，避免 1s 轮询浪费 CPU
        this._tokenDisconnectedRetries++;
        const backoff = Math.min(minimumDelay * Math.pow(2, this._tokenDisconnectedRetries), 60_000);
        this._tokenRefreshTimer = globalThis.setTimeout(scheduleRefresh, backoff);
        return;
      }
      // 连接恢复后重置退避计数器
      this._tokenDisconnectedRetries = 0;

      let identity = this._identity;
      if (!identity) {
        this._tokenRefreshTimer = globalThis.setTimeout(scheduleRefresh, minimumDelay);
        return;
      }

      const expiresAt = this._auth.getAccessTokenExpiry(identity);
      if (expiresAt === null) {
        this._tokenRefreshTimer = globalThis.setTimeout(scheduleRefresh, minimumDelay);
        return;
      }

      const delay = Math.max((expiresAt - lead) * 1000 - Date.now(), minimumDelay);
      this._tokenRefreshTimer = globalThis.setTimeout(async () => {
        if (this._state !== 'connected' || !this._gatewayUrl || this._closing) {
          scheduleRefresh();
          return;
        }
        try {
          identity = await this._auth.refreshCachedTokens(this._gatewayUrl!, identity!);
          this._identity = identity;
          if (this._sessionParams && identity.access_token) {
            this._sessionParams.access_token = identity.access_token;
          }
          await this._dispatcher.publish('token.refreshed', {
            aid: identity.aid,
            expires_at: identity.access_token_expires_at,
          });
        } catch (exc) {
          if (exc instanceof AuthError) {
            console.warn('token 刷新失败，下次重试:', exc);
          } else {
            this._dispatcher.publish('connection.error', { error: formatCaughtError(exc) });
          }
        }
        scheduleRefresh();
      }, delay);
    };

    scheduleRefresh();
  }

  /** Prekey 轮换定时器：定期检查本地 prekey 数量，不足时自动补充上传 */
  private _startPrekeyRefresh(): void {
    if (this._prekeyRefreshTimer !== null) return;
    const PREKEY_CHECK_INTERVAL = 3600_000; // 1 小时
    const PREKEY_LOW_THRESHOLD = 5;         // 低于此数量则补充
    const PREKEY_UPLOAD_COUNT = 10;         // 每次补充上传的数量

    const check = async () => {
      try {
        if (this._state !== 'connected' || !this._e2ee) return;
        const aid = this._identity?.aid;
        if (!aid) return;

        // 从 keystore 加载本地 prekey 并计数
        let remaining = 0;
        try {
          const deviceId = String(this._deviceId ?? '').trim();
          let prekeys: Record<string, unknown> = {};
          if (typeof this._keystore.loadE2EEPrekeys === 'function') {
            prekeys = (await this._keystore.loadE2EEPrekeys(aid, deviceId)) ?? {};
          }
          remaining = Object.keys(prekeys).length;
        } catch {
          // keystore 读取失败时保守地触发补充
          remaining = 0;
        }

        // prekey 不足时批量生成并上传
        if (remaining < PREKEY_LOW_THRESHOLD) {
          const uploadCount = PREKEY_UPLOAD_COUNT - remaining;
          for (let i = 0; i < uploadCount; i++) {
            await this._uploadPrekey();
          }
        }
      } catch (exc) {
        console.warn('[aun_core] prekey 定时刷新失败:', exc);
      }

      // 仍处于连接状态时安排下一次检查
      if (this._state === 'connected') {
        this._prekeyRefreshTimer = globalThis.setTimeout(check, PREKEY_CHECK_INTERVAL);
      }
    };

    // 首次检查延迟 1 小时后启动
    this._prekeyRefreshTimer = globalThis.setTimeout(check, PREKEY_CHECK_INTERVAL);
  }

  private _extractConsumedPrekeyId(message: ConsumedPrekeyCarrier | null | undefined): string {
    if (!message) return '';
    const e2ee = message.e2ee;
    if (!e2ee) return '';
    if (e2ee.encryption_mode !== 'prekey_ecdh_v2') return '';
    return String(e2ee.prekey_id ?? '').trim();
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

    this._safeAsync((async () => {
      try {
        await this._uploadPrekey();
        this._prekeyReplenished.add(prekeyId);
      } catch (exc) {
        console.warn(`消费 prekey ${prekeyId} 后补充 current prekey 失败:`, exc);
      } finally {
        this._prekeyReplenishInflight.delete(prekeyId);
      }
    })());
  }

  /** 群组 epoch 后台任务 */
  private _startGroupEpochTasks(): void {
    // 群组 E2EE 是必备能力，始终执行 epoch 清理

    // 旧 epoch 清理（每小时）
    if (this._groupEpochCleanupTimer === null) {
      this._groupEpochCleanupTimer = setInterval(async () => {
        if (this._state !== 'connected' || this._closing || !this._aid) return;
        try {
          const groupIds = typeof this._keystore.listGroupSecretIds === 'function'
            ? await this._keystore.listGroupSecretIds(this._aid!)
            : [];
          const retention = this.configModel.oldEpochRetentionSeconds;
          for (const gid of groupIds) {
            await this._groupE2ee.cleanup(gid, retention);
          }
        } catch (exc) {
          console.warn('epoch 清理失败:', exc);
        }
      }, 3600 * 1000);
    }

    // 定时 epoch 轮换
    const rotateInterval = this.configModel.epochAutoRotateInterval;
    if (rotateInterval > 0 && this._groupEpochRotateTimer === null) {
      this._groupEpochRotateTimer = setInterval(async () => {
        if (this._state !== 'connected' || this._closing || !this._aid) return;
        try {
          const groupIds = typeof this._keystore.listGroupSecretIds === 'function'
            ? await this._keystore.listGroupSecretIds(this._aid!)
            : [];
          for (const gid of groupIds) {
            await this._maybeLeadRotateGroupEpoch(gid);
          }
        } catch (exc) {
          console.warn('epoch 定时轮换失败:', exc);
        }
      }, rotateInterval * 1000);
    }

    // 内存缓存定时清理（每小时扫描过期条目）
    if (this._cacheCleanupTimer === null) {
      this._cacheCleanupTimer = setInterval(() => {
        const nowSec = Date.now() / 1000;
        for (const [k, v] of this._certCache) {
          if (nowSec >= v.refreshAfter) this._certCache.delete(k);
        }
        for (const [k, v] of this._peerPrekeysCache) {
          if (nowSec >= v.expireAt) this._peerPrekeysCache.delete(k);
        }
        if (this._gapFillDone.size > 10000) {
          const arr = [...this._gapFillDone];
          this._gapFillDone = new Set(arr.slice(arr.length - 5000));
        }
        this._e2ee.cleanExpiredCaches();
        this._groupE2ee.cleanExpiredCaches();
        this._auth.cleanExpiredCaches();
      }, 3600_000);
    }
  }

  // ── 内部：断线重连 ────────────────────────────────

  /** 不重连 close code 集合：认证失败/权限错误/被踢等，重连无意义 */
  private static readonly _NO_RECONNECT_CODES = new Set([4001, 4003, 4008, 4009, 4010, 4011]);

  /** 处理服务端主动断开通知 event/gateway.disconnect */
  private _onGatewayDisconnect(data: any): void {
    const code = data?.code;
    const reason = data?.reason ?? '';
    console.warn(`[aun_core] 服务端主动断开: code=${code}, reason=${reason}`);
    this._serverKicked = true;
  }

  private async _handleTransportDisconnect(error: Error | null, closeCode?: number): Promise<void> {
    if (this._closing || this._state === 'closed') return;
    this._state = 'disconnected';
    // 先停止后台任务，避免心跳/token刷新在重连期间继续触发
    this._stopBackgroundTasks();
    await this._dispatcher.publish('connection.state', {
      state: this._state,
      error,
    });

    if (!this._sessionOptions.auto_reconnect) return;
    if (this._reconnectActive) return;

    // 不重连 close code（认证失败/权限错误/被踢等）或服务端通知断开：抑制重连
    if (this._serverKicked || (closeCode !== undefined && AUNClient._NO_RECONNECT_CODES.has(closeCode))) {
      this._state = 'terminal_failed';
      const reason = this._serverKicked ? 'server kicked' : `close code ${closeCode}`;
      console.warn(`[aun_core] 抑制自动重连: ${reason}`);
      await this._dispatcher.publish('connection.state', {
        state: this._state, error, reason,
      });
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

    for (let attempt = 1; !this._reconnectAbort?.signal.aborted; attempt++) {
      // R1 fix: max_attempts 检查在循环顶部，覆盖所有路径（含 health-fail）
      if (maxAttempts > 0 && attempt > maxAttempts) {
        this._state = 'terminal_failed';
        this._reconnectActive = false;
        this._reconnectAbort = null;
        await this._dispatcher.publish('connection.state', {
          state: this._state,
          attempt: attempt - 1,
          reason: 'max_attempts_exhausted',
        });
        return;
      }

      this._state = 'reconnecting';
      await this._dispatcher.publish('connection.state', {
        state: this._state,
        attempt,
      });

      try {
        await this._sleep(reconnectSleepDelaySeconds(delay, maxBaseDelay) * 1000);
        if (this._reconnectAbort?.signal.aborted) {
          this._reconnectActive = false;
          return;
        }
        // 重连前先 GET /health 探测，不健康则跳过本轮
        if (this._gatewayUrl) {
          const healthy = await this._discovery.checkHealth(this._gatewayUrl, 5000);
          if (!healthy) {
            delay = Math.min(delay * 2, maxBaseDelay);
            continue;
          }
        }
        await this._transport.close();
        if (!this._sessionParams) {
          throw new StateError('missing connect params for reconnect');
        }
        await this._connectOnce(this._sessionParams, true);
        this._reconnectActive = false;
        this._reconnectAbort = null;
        return;
      } catch (exc) {
        await this._dispatcher.publish('connection.error', {
          error: formatCaughtError(exc),
          attempt,
        });
        if (!this._shouldRetryReconnect(exc as Error)) {
          this._state = 'terminal_failed';
          this._reconnectActive = false;
          this._reconnectAbort = null;
          await this._dispatcher.publish('connection.state', {
            state: this._state,
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
        const state = await loadAll(aid, deviceId, slotId);
        if (this._seqTrackerContext !== context) return;
        if (state && typeof state === 'object' && Object.keys(state).length > 0) {
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
          this._seqTracker.restoreState(state as Record<string, number>);
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

  private _currentSeqTrackerContext(): string | null {
    if (!this._aid) return null;
    return JSON.stringify([this._aid, this._deviceId, this._slotId]);
  }

  private _resetSeqTrackingState(): void {
    this._seqTracker = new SeqTracker();
    this._seqTrackerContext = null;
    this._gapFillDone.clear();
    this._pushedSeqs.clear();
    this._groupSynced.clear();
    this._p2pSynced = false;
  }

  private _refreshSeqTrackerContext(): void {
    const nextContext = this._currentSeqTrackerContext();
    if (nextContext === this._seqTrackerContext) return;
    this._seqTracker = new SeqTracker();
    this._gapFillDone.clear();
    this._pushedSeqs.clear();
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

  /** 发布 E2EE 编排错误事件 */
  private _logE2eeError(stage: string, groupId: string, aid: string, exc: Error): void {
    try {
      this._dispatcher.publish('e2ee.orchestration_error', {
        stage,
        group_id: groupId,
        aid,
        error: String(exc),
      });
    } catch { /* 日志本身不应阻断主流程 */ }
  }

  /** 安全执行异步操作（不阻塞调用方，错误打 warning 便于排障） */
  private _safeAsync(promise: Promise<RpcResult | void>): void {
    promise.catch((exc) => {
      console.warn('后台任务异常:', exc);
    });
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
