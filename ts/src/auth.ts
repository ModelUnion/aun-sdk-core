/**
 * AuthFlow — 认证流程管理
 *
 * Node.js 完整实现，与 Python SDK 的 AuthFlow 接口对齐。
 * 功能：
 * - AID 创建（在 Gateway 注册身份）
 * - 两阶段挑战-应答认证（login1 + login2）
 * - 证书链验证（chain + CRL + OCSP）
 * - Token 刷新
 * - 会话初始化
 * - 证书恢复与自动续期
 */

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as https from 'node:https';
import * as path from 'node:path';
import { URL, fileURLToPath } from 'node:url';

import WebSocket from 'ws';

import { AuthError, StateError, ValidationError, AUNError, IdentityConflictError, mapRemoteError } from './errors.js';
import type { CryptoProvider } from './crypto.js';
import type { TokenStore } from './keystore/index.js';
import type { RPCTransport } from './transport.js';
import type { DnsResilientNet } from './net.js';
import {
  isJsonObject,
  type IdentityRecord,
  type JsonObject,
  type JsonValue,
  type RpcMessage,
  type RpcParams,
  type RpcResult,
} from './types.js';

import type { ModuleLogger } from './logger.js';
import { VERSION as AUN_SDK_VERSION } from './version.js';

const _noopLogger: ModuleLogger = {
  error: () => {},
  warn:  () => {},
  info:  () => {},
  debug: () => {},
};

const AUN_SDK_LANG = 'typescript';
const SENSITIVE_RPC_LOG_KEYS = new Set([
  'access_token',
  'refresh_token',
  'kite_token',
  'token',
]);

function _redactRpcLogPayload(value: unknown, key: string = '', depth: number = 0): unknown {
  const keyLower = key.toLowerCase();
  if (SENSITIVE_RPC_LOG_KEYS.has(keyLower) || keyLower.endsWith('_token')) {
    const text = String(value ?? '');
    if (!text) return '';
    const digest = crypto.createHash('sha256').update(text).digest('hex').slice(0, 12);
    return `<redacted len=${text.length} sha256=${digest}>`;
  }
  if (depth >= 6) return '<max-depth>';
  if (Array.isArray(value)) {
    return value.map((item) => _redactRpcLogPayload(item, '', depth + 1));
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [childKey, childValue] of Object.entries(value as Record<string, unknown>)) {
      out[childKey] = _redactRpcLogPayload(childValue, childKey, depth + 1);
    }
    return out;
  }
  return value;
}

// ── 签名验证辅助 ──────────────────────────────────────────────

/**
 * 验证签名：支持 ECDSA P-256 (SHA256)、ECDSA P-384 (SHA384)、Ed25519。
 * 与 Python _verify_signature 完全对齐。
 */
function _verifySignature(pubKey: crypto.KeyObject, signature: Buffer, data: Buffer): void {
  const asymKeyDetails = pubKey.asymmetricKeyType;

  if (asymKeyDetails === 'ed25519') {
    const ok = crypto.verify(null, data, pubKey, signature);
    if (!ok) throw new AuthError('ed25519 signature verification failed');
    return;
  }

  if (asymKeyDetails === 'ec') {
    // 通过导出公钥的 JWK 判断曲线
    const jwk = pubKey.export({ format: 'jwk' }) as ExportedJwk;
    const crv = jwk.crv;
    const alg = crv === 'P-384' ? 'SHA384' : 'SHA256';
    const ok = crypto.verify(alg, data, pubKey, signature);
    if (!ok) throw new AuthError(`ecdsa ${alg} signature verification failed`);
    return;
  }

  throw new AuthError(`unsupported public key type: ${asymKeyDetails}`);
}

// ── X.509 辅助函数 ────────────────────────────────────────────

/** 将 PEM bundle 拆分为独立的 PEM 字符串数组 */
function _splitPemBundle(bundleText: string): string[] {
  const marker = '-----END CERTIFICATE-----';
  const certs: string[] = [];
  for (const part of bundleText.split(marker)) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    certs.push(`${trimmed}\n${marker}\n`);
  }
  return certs;
}

/** 加载 PEM 字符串为 X509Certificate 对象 */
function _loadX509(pem: string): crypto.X509Certificate {
  return new crypto.X509Certificate(pem);
}

/** 从 X509Certificate 提取公钥 KeyObject */
function _extractPublicKey(cert: crypto.X509Certificate): crypto.KeyObject {
  // Node.js 18+: cert.publicKey 已经是 KeyObject 类型
  const pk = cert.publicKey;
  if (pk && typeof pk === 'object' && 'type' in pk) {
    return pk as crypto.KeyObject;
  }
  // fallback: 从 PEM 格式创建
  return crypto.createPublicKey(cert.toString());
}

const CERT_CLOCK_SKEW_MS = 300_000;

/** 检查证书时间有效性，允许测试环境和容器之间存在短暂时钟偏差 */
function _ensureCertTimeValid(cert: crypto.X509Certificate, label: string, nowMs: number): void {
  const notBefore = new Date(cert.validFrom).getTime();
  const notAfter = new Date(cert.validTo).getTime();
  if (nowMs + CERT_CLOCK_SKEW_MS < notBefore) {
    throw new AuthError(`${label} is not yet valid`);
  }
  if (nowMs - CERT_CLOCK_SKEW_MS > notAfter) {
    throw new AuthError(`${label} has expired`);
  }
}

/**
 * 检查 BasicConstraints 扩展中 CA=true。
 * Node.js crypto.X509Certificate 不直接暴露 BasicConstraints，
 * 但 cert.ca 属性（Node 20+）可用，或者检查 keyUsage。
 * 这里通过 cert 的 infoAccess / 文本表示解析。
 */
function _isCaCert(cert: crypto.X509Certificate): boolean {
  // Node.js X509Certificate 在 v20+ 提供 .ca 属性
  const compatCert = cert as crypto.X509Certificate & { ca?: boolean };
  if (typeof compatCert.ca === 'boolean') {
    return compatCert.ca;
  }
  // 降级：解析 cert 文本表示中的 BasicConstraints
  const text = cert.toString();
  // 检查是否包含 CA:TRUE
  if (/CA:TRUE/i.test(text)) return true;
  // 自签证书（issuer == subject）也视为 CA
  if (cert.issuer === cert.subject) return true;
  return false;
}

/** 检查证书是否为自签（issuer == subject） */
function _isSelfSigned(cert: crypto.X509Certificate): boolean {
  return cert.issuer === cert.subject;
}

/**
 * 验证 cert 是否由 issuerCert 签发。
 * 使用 X509Certificate.checkIssued (Node 18+)。
 */
function _checkIssuedBy(cert: crypto.X509Certificate, issuerCert: crypto.X509Certificate): boolean {
  if (typeof cert.checkIssued === 'function') {
    return cert.checkIssued(issuerCert);
  }
  // 降级比较 issuer/subject
  return cert.issuer === issuerCert.subject;
}

/**
 * 验证 cert 的签名是否由 issuerCert 的公钥签署。
 * 使用 X509Certificate.verify (Node 18+)。
 */
function _verifyCertSignedBy(cert: crypto.X509Certificate, issuerCert: crypto.X509Certificate): boolean {
  if (typeof cert.verify === 'function') {
    return cert.verify(_extractPublicKey(issuerCert));
  }
  // 如果 verify 不可用，只能信赖 checkIssued
  return _checkIssuedBy(cert, issuerCert);
}

/** 获取证书序列号的十六进制字符串（小写） */
function _certSerialHex(cert: crypto.X509Certificate): string {
  return cert.serialNumber.toLowerCase();
}

/** 获取证书的 Subject CN */
function _certSubjectCN(cert: crypto.X509Certificate): string | null {
  // cert.subject 格式: "CN=xxx\nO=yyy\n..."
  const match = cert.subject.match(/CN=([^\n]+)/);
  return match ? match[1].trim() : null;
}

/** 获取证书 DER 编码（用于去重比较） */
function _certDer(cert: crypto.X509Certificate): Buffer {
  return Buffer.from(cert.raw);
}

// ── HTTP 辅助 ─────────────────────────────────────────────────

/** 将 WebSocket URL 转换为 HTTP URL + 路径 */
function _gatewayHttpUrl(gatewayUrl: string, urlPath: string): string {
  const parsed = new URL(gatewayUrl);
  const scheme = parsed.protocol === 'wss:' ? 'https:' : 'http:';
  return `${scheme}//${parsed.host}${urlPath}`;
}

/** 发起 HTTP GET 请求，返回文本内容 */
async function _fetchText(url: string, verifySsl: boolean, net?: DnsResilientNet | null): Promise<string> {
  try {
    if (net) {
      return await net.httpGetText(url, 5_000);
    }
    return await _httpGet(url, verifySsl);
  } catch (err) {
    throw new AuthError(`failed to fetch ${url}: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/** 发起 HTTP GET 请求，返回 JSON 对象 */
async function _fetchJson(url: string, verifySsl: boolean, net?: DnsResilientNet | null): Promise<JsonObject> {
  const text = await _fetchText(url, verifySsl, net);
  try {
    const payload = JSON.parse(text);
    if (!isJsonObject(payload)) {
      throw new AuthError(`invalid JSON payload from ${url}`);
    }
    return payload;
  } catch (err) {
    if (err instanceof AuthError) throw err;
    throw new AuthError(`invalid JSON from ${url}: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/** 底层 HTTP GET 实现，兼容 http/https + SSL 控制 */
function _httpGet(url: string, verifySsl: boolean): Promise<string> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;
    const options: https.RequestOptions = {
      timeout: 5000,
    };
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

// ── 缓存类型 ──────────────────────────────────────────────────

interface CrlCacheEntry {
  revokedSerials: Set<string>;
  nextRefreshAt: number;
}

interface OcspCacheEntry {
  status: string;
  nextRefreshAt: number;
}

// ── WebSocket 短连接 RPC ──────────────────────────────────────

/** 默认连接工厂：创建临时 WebSocket 连接 */
type ConnectionFactory = (url: string) => Promise<WebSocket>;

function _defaultConnectionFactory(url: string): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, {
      handshakeTimeout: 5000,
      rejectUnauthorized: false,
    });
    ws.on('open', () => resolve(ws));
    ws.on('error', (err) => reject(new AuthError(`websocket connect failed: ${err.message}`)));
  });
}

// ── AuthFlow ──────────────────────────────────────────────────

export class AuthFlow {
  private static readonly _INSTANCE_STATE_FIELDS = [
    'access_token',
    'refresh_token',
    'kite_token',
    'access_token_expires_at',
  ] as const;

  private _logger: ModuleLogger;
  private _tokenStore: TokenStore;
  private _crypto: CryptoProvider;
  private _aid: string | null;
  private _deviceId: string;
  private _slotId: string;
  private _verifySsl: boolean;
  private _net: DnsResilientNet | null;
  private _connectionFactory: ConnectionFactory;
  private _rootCaPath: string | null;
  private _chainCacheTtl: number;

  // 根证书（启动时加载）
  private _rootCerts: crypto.X509Certificate[];

  // Gateway CA 链缓存：gateway_url -> PEM 字符串数组
  private _gatewayChainCache: Map<string, string[]> = new Map();
  // Gateway CRL 缓存：gateway_url -> CRL 缓存条目
  private _gatewayCrlCache: Map<string, CrlCacheEntry> = new Map();
  // Gateway OCSP 缓存：gateway_url -> (serial_hex -> OCSP 缓存条目)
  private _gatewayOcspCache: Map<string, Map<string, OcspCacheEntry>> = new Map();
  // 证书链验证结果缓存：cert_serial -> verified_at (ms)
  private _chainVerifiedCache: Map<string, number> = new Map();
  // Gateway CA 链预验证标记：cache_key -> verified
  private _gatewayCaVerified: Map<string, boolean> = new Map();
  // 调用方注入的内存私钥（由 AUNClient.loadIdentity 传入，不走 tokenStore 解密）
  private _memIdentity: IdentityRecord | null = null;

  constructor(opts: {
    tokenStore: TokenStore;
    crypto: CryptoProvider;
    aid?: string | null;
    deviceId?: string;
    slotId?: string;
    connectionFactory?: ConnectionFactory;
    rootCaPath?: string | null;
    chainCacheTtl?: number;
    verifySsl?: boolean;
    logger?: ModuleLogger;
    net?: DnsResilientNet | null;
  }) {
    this._logger = opts.logger ?? _noopLogger;
    this._tokenStore = opts.tokenStore;
    this._crypto = opts.crypto;
    this._aid = opts.aid ?? null;
    this._deviceId = String(opts.deviceId ?? '').trim();
    this._slotId = String(opts.slotId ?? '').trim();
    this._connectionFactory = opts.connectionFactory ?? _defaultConnectionFactory;
    this._rootCaPath = opts.rootCaPath ?? null;
    this._net = opts.net ?? null;
    this._verifySsl = opts.verifySsl ?? false;
    this._chainCacheTtl = (opts.chainCacheTtl ?? 86400) * 1000; // 转为毫秒
    this._rootCerts = this._loadRootCerts(this._rootCaPath);
  }

  // ── 公开方法 ────────────────────────────────────────────────

  /**
   * 注入内存私钥（由 AUNClient.loadIdentity 调用）。
   * AuthFlow 内部不再从 tokenStore 解密私钥，只使用此处注入的明文。
   */
  setIdentity(identity: IdentityRecord | null): void {
    this._memIdentity = identity;
    if (identity?.aid) this._aid = String(identity.aid);
  }

  /** 加载身份信息（密钥对 + 证书 + 元数据） */
  loadIdentity(aid?: string): IdentityRecord {
    const identity = this._loadIdentityOrRaise(aid);
    const cert = this._tokenStore.loadCert(String(identity.aid));
    if (cert) identity.cert = cert;
    const instanceState = this._loadInstanceState(String(identity.aid));
    if (instanceState && typeof instanceState === 'object') {
      // 只合并 _INSTANCE_STATE_FIELDS 定义的字段，防止 instance_state 表中的脏数据
      // 覆盖从 key.json 加载的真实私钥（private_key_pem）等核心字段。
      for (const key of AuthFlow._INSTANCE_STATE_FIELDS) {
        if (key in instanceState) {
          (identity as Record<string, unknown>)[key] = instanceState[key];
        }
      }
    }
    return identity;
  }

  /** 加载身份信息，不存在时返回 null */
  loadIdentityOrNone(aid?: string): IdentityRecord | null {
    try {
      return this.loadIdentity(aid);
    } catch (e) {
      if (e instanceof StateError) return null;
      throw e;
    }
  }

  /** 与 Browser/JS SDK 对齐的别名：加载身份信息，不存在时返回 null */
  loadIdentityOrNull(aid?: string): IdentityRecord | null {
    return this.loadIdentityOrNone(aid);
  }

  /** 获取 access_token 的过期时间戳（秒） */
  getAccessTokenExpiry(identity: IdentityRecord): number | null {
    const expiresAt = identity.access_token_expires_at;
    if (typeof expiresAt === 'number') return expiresAt;
    return null;
  }

  setInstanceContext(opts: { deviceId: string; slotId?: string }): void {
    this._deviceId = String(opts.deviceId ?? '').trim();
    this._slotId = String(opts.slotId ?? '').trim();
  }

  /**
   * 认证（登录）到 Gateway。
   * 执行两阶段挑战-应答认证，返回 token 信息。
   */
  async authenticate(
    gatewayUrl: string,
    opts?: { aid?: string },
  ): Promise<JsonObject> {
    const tStart = Date.now();
    let identity = this._loadIdentityOrRaise(opts?.aid);
    this._logger.debug(`authenticate enter: aid=${identity.aid}, gateway=${gatewayUrl}`);
    try {
      // 优先复用 tokenStore 里的 cached access_token（未过期且有 refresh_token）
      // 避免每次调 authenticate 都走两阶段重登的网络往返
      // 注意：_loadIdentityOrRaise 不带 instance_state（access_token 等），
      // 这里需要主动走 _loadInstanceState 拿到 token
      const instanceState = this._loadInstanceState(String(identity.aid)) || {};
      const identityWithState: IdentityRecord = { ...identity, ...instanceState };
      const cachedToken = AuthFlow._getCachedAccessToken(identityWithState);
      const cachedRefresh = String(identityWithState.refresh_token ?? '');
      if (cachedToken && cachedRefresh) {
        // 复用 cached token 前必须验证本地身份完整性：
        // cert 存在 + cert 公钥 == keypair 公钥 + cert 时间窗口有效。
        // 任何一项不通过 → 不复用，走两步重登（或抛错）。
        const credIssue = this._validateCachedCredentials(identity);
        if (!credIssue) {
          this._logger.debug(`authenticate reusing cached token: aid=${identity.aid} expires_at=${identityWithState.access_token_expires_at}`);
          this._aid = String(identity.aid);
          return {
            aid: identity.aid,
            access_token: cachedToken,
            refresh_token: cachedRefresh,
            expires_at: identityWithState.access_token_expires_at,
            gateway: gatewayUrl,
          };
        } else {
          this._logger.info(`cached token not reused (credential issue): aid=${identity.aid} reason=${credIssue}`);
        }
      }

      if (!identity.cert) {
        // 本地有密钥但无证书——尝试从 PKI 下载恢复
        try {
          identity = await this._recoverCertViaDownload(gatewayUrl, identity);
          this._persistIdentity(identity);
        } catch (e) {
          throw new StateError(
            `local certificate missing and recovery failed: ${e instanceof Error ? e.message : String(e)}. ` +
            `Run auth.registerAid() to register a new identity.`,
          );
        }
      }

      // 防线 B：发起两步登录前显式校验 cert 公钥与本地 keypair 公钥一致。
      this._assertCertMatchesLocalKeypair(identity);

      let login: JsonObject;
      try {
        login = await this._login(gatewayUrl, identity);
        this._logger.debug(`auth login ok: aid=${identity.aid}`);
      } catch (e) {
        // 注册和登录彻底分离：登录失败绝不触发自动注册。
        // 服务端报"not registered"时，应用层应当显式调 registerAid。
        throw e;
      }
      AuthFlow._rememberTokens(identity, login);
      await this._validateNewCert(identity, gatewayUrl);
      this._persistIdentity(identity);
      this._aid = String(identity.aid);
      this._logger.debug(`authenticate exit: elapsed=${Date.now() - tStart}ms aid=${identity.aid}`);
      return {
        aid: identity.aid,
        access_token: identity.access_token,
        refresh_token: identity.refresh_token,
        expires_at: identity.access_token_expires_at,
        gateway: gatewayUrl,
      };
    } catch (err) {
      this._logger.debug(`authenticate exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /**
   * 确保已认证（自动创建 + 登录）。
   * 如果没有本地身份则创建，然后执行登录流程。
   */
  async ensureAuthenticated(gatewayUrl: string): Promise<AuthContext> {
    const tStart = Date.now();
    this._logger.debug(`ensureAuthenticated enter: gateway=${gatewayUrl}`);
    try {
      // 注册和登录彻底分离：无身份直接抛错，绝不再隐式生成密钥。
      const identity = this._loadIdentityOrRaise();
      if (!identity.cert) {
        throw new StateError(
          `local identity for aid ${identity.aid} has no certificate; ` +
          `call auth.authenticate() to attempt cert recovery, or auth.registerAid() if this is a fresh registration.`,
        );
      }
      // 防线 B：发起两步登录前显式校验
      this._assertCertMatchesLocalKeypair(identity);

      const login = await this._login(gatewayUrl, identity);
      AuthFlow._rememberTokens(identity, login);
      await this._validateNewCert(identity, gatewayUrl);
      this._persistIdentity(identity);

      const token = identity.access_token || identity.token || identity.kite_token;
      if (!token) {
        throw new AuthError('login2 did not return access token');
      }
      this._logger.debug(`ensureAuthenticated exit: elapsed=${Date.now() - tStart}ms aid=${identity.aid}`);
      return { token, identity };
    } catch (err) {
      this._logger.debug(`ensureAuthenticated exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /**
   * 刷新缓存的 token。
   * 使用 refresh_token 获取新的 access_token。
   */
  async refreshCachedTokens(
    gatewayUrl: string,
    identity: IdentityRecord,
  ): Promise<IdentityRecord> {
    const tStart = Date.now();
    const refreshToken = String(identity.refresh_token || '');
    if (!refreshToken) {
      this._logger.error(`token refresh failed: missing refresh_token, aid=${identity.aid}`);
      this._clearCachedTokens(identity, 'missing refresh_token');
      throw new AuthError('missing refresh_token');
    }
    this._logger.debug(`refreshCachedTokens enter: aid=${identity.aid}`);
    try {
      const refreshed = await this._refreshAccessToken(gatewayUrl, refreshToken, identity);
      AuthFlow._rememberTokens(identity, refreshed);
      await this._validateNewCert(identity, gatewayUrl);
      this._persistIdentity(identity);
      this._logger.debug(`refreshCachedTokens exit: elapsed=${Date.now() - tStart}ms aid=${identity.aid}`);
      return identity;
    } catch (err) {
      if (this._refreshFailureRequiresRelogin(err)) {
        this._clearCachedTokens(identity, err instanceof Error ? err.message : String(err));
      }
      this._logger.debug(`refreshCachedTokens exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /**
   * 使用 token 初始化 WebSocket 会话。
   * 发送 auth.connect RPC 完成会话握手。
   */
  async initializeWithToken(
    transport: RPCTransport,
    challenge: RpcMessage | null,
    accessToken: string,
    opts?: {
      deviceId?: string;
      slotId?: string;
      deliveryMode?: JsonObject | null;
      connectionKind?: string;
      shortTtlMs?: number;
      extraInfo?: Record<string, unknown>;
    },
  ): Promise<JsonObject> {
    const tStart = Date.now();
    this._logger.debug(`initializeWithToken enter: deviceId=${opts?.deviceId ?? ''}, slotId=${opts?.slotId ?? ''}`);
    try {
      const nonce = this._extractChallengeNonce(challenge);
      this.setInstanceContext({
        deviceId: String(opts?.deviceId ?? ''),
        slotId: String(opts?.slotId ?? ''),
      });
      const hello = await this._initializeSession(transport, nonce, accessToken, {
        deviceId: String(opts?.deviceId ?? ''),
        slotId: String(opts?.slotId ?? ''),
        deliveryMode: opts?.deliveryMode ?? null,
        connectionKind: opts?.connectionKind,
        shortTtlMs: opts?.shortTtlMs,
        extraInfo: opts?.extraInfo,
      });
      this._logger.debug(`initializeWithToken exit: elapsed=${Date.now() - tStart}ms`);
      return hello;
    } catch (err) {
      this._logger.debug(`initializeWithToken exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /**
   * 连接会话（自动选择认证策略）。
   * 依次尝试：显式 token → 缓存 token → 刷新 token → 完整重认证。
   */
  async connectSession(
    transport: RPCTransport,
    challenge: RpcMessage | null,
    gatewayUrl: string,
    opts?: {
      accessToken?: string;
      deviceId?: string;
      slotId?: string;
      deliveryMode?: JsonObject | null;
      connectionKind?: string;
      shortTtlMs?: number;
      extraInfo?: Record<string, unknown>;
    },
  ): Promise<AuthContext> {
    const tStart = Date.now();
    const nonce = this._extractChallengeNonce(challenge);
    const deviceId = String(opts?.deviceId ?? '');
    const slotId = String(opts?.slotId ?? '');
    const deliveryMode = opts?.deliveryMode ?? null;
    const connectionKind = opts?.connectionKind;
    const shortTtlMs = opts?.shortTtlMs;
    const extraInfo = opts?.extraInfo;
    this.setInstanceContext({ deviceId, slotId });

    this._logger.debug(`connectSession enter: gateway=${gatewayUrl}, device_id=${deviceId}, slot_id=${slotId}, has_explicit_token=${!!opts?.accessToken}, has_challenge_nonce=${!!nonce}`);

    try {
      let identity: IdentityRecord | null;
      try {
        identity = this.loadIdentity();
      } catch {
        identity = null;
      }

      // 策略 1：显式 token
      const explicitToken = String(opts?.accessToken || '');
      if (explicitToken && identity !== null) {
        try {
          const hello = await this._initializeSession(transport, nonce, explicitToken, {
            deviceId,
            slotId,
            deliveryMode,
            connectionKind,
            shortTtlMs,
            extraInfo,
          });
          identity.access_token = explicitToken;
          this._persistIdentity(identity);
          this._logger.debug(`connectSession exit: elapsed=${Date.now() - tStart}ms strategy=explicit_token aid=${String(identity.aid ?? '')}`);
          return { token: explicitToken, identity, hello };
        } catch (exc) {
          if (!(exc instanceof AuthError)) throw exc;
          this._logger.debug(`explicit_token auth failed, try next method: ${exc.message}`);
        }
      }

      // 无本地身份时，执行完整认证
      if (identity === null) {
        const authContext = await this.ensureAuthenticated(gatewayUrl);
        const token = String(authContext.token);
        const hello = await this._initializeSession(transport, nonce, token, {
          deviceId,
          slotId,
          deliveryMode,
          connectionKind,
          shortTtlMs,
          extraInfo,
        });
        this._logger.debug(`connectSession exit: elapsed=${Date.now() - tStart}ms strategy=ensure_authenticated aid=${String(authContext.identity?.aid ?? '')}`);
        return { ...authContext, hello };
      }

      // 策略 2：缓存的 access_token
      const cachedToken = AuthFlow._getCachedAccessToken(identity);
      if (cachedToken) {
        try {
          const hello = await this._initializeSession(transport, nonce, cachedToken, {
            deviceId,
            slotId,
            deliveryMode,
            connectionKind,
            shortTtlMs,
            extraInfo,
          });
          this._logger.debug(`connectSession exit: elapsed=${Date.now() - tStart}ms strategy=cached_token aid=${String(identity.aid ?? '')}`);
          return { token: cachedToken, identity, hello };
        } catch (exc) {
          if (!(exc instanceof AuthError)) throw exc;
          this._logger.debug(`cached_token auth failed, try refresh: ${exc.message}`);
        }
      }

      // 策略 3：refresh_token
      const refreshToken = String(identity.refresh_token || '');
      if (refreshToken) {
        try {
          identity = await this.refreshCachedTokens(gatewayUrl, identity);
          const newCachedToken = AuthFlow._getCachedAccessToken(identity);
          if (newCachedToken) {
            const hello = await this._initializeSession(transport, nonce, newCachedToken, {
              deviceId,
              slotId,
              deliveryMode,
              connectionKind,
              shortTtlMs,
              extraInfo,
            });
            this._logger.debug(`connectSession exit: elapsed=${Date.now() - tStart}ms strategy=refresh_token aid=${String(identity.aid ?? '')}`);
            return { token: newCachedToken, identity, hello };
          }
        } catch (exc) {
          if (!(exc instanceof AuthError)) throw exc;
          if (this._refreshFailureRequiresRelogin(exc)) {
            this._clearCachedTokens(identity, exc.message);
          }
          this._logger.debug(`refresh_token auth failed, will re-login: ${exc.message}`);
        }
      }

      // 策略 4：完整重认证
      const login = await this.authenticate(gatewayUrl, { aid: identity.aid as string | undefined });
      const token = String(login.access_token || '');
      if (!token) {
        throw new AuthError('authenticate did not return access_token');
      }
      const hello = await this._initializeSession(transport, nonce, token, {
        deviceId,
        slotId,
        deliveryMode,
        connectionKind,
        shortTtlMs,
        extraInfo,
      });
      identity = this.loadIdentity(identity.aid as string | undefined);
      this._logger.debug(`connectSession exit: elapsed=${Date.now() - tStart}ms strategy=full_reauth aid=${String(identity?.aid ?? '')}`);
      return { token, identity, hello };
    } catch (err) {
      this._logger.debug(`connectSession exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /**
   * 验证对端证书：时间有效性 + 链验证 + CRL + OCSP + AID 绑定。
   * 用于 E2EE 握手中验证通信对端的身份证书。
   */
  async verifyPeerCertificate(
    gatewayUrl: string,
    certPem: string,
    expectedAid: string,
  ): Promise<void> {
    const tStart = Date.now();
    this._logger.debug(`verifyPeerCertificate enter: aid=${expectedAid}, gateway=${gatewayUrl}`);
    try {
      const cert = _loadX509(certPem);
      const nowMs = Date.now();
      _ensureCertTimeValid(cert, 'peer certificate', nowMs);

      await this._verifyAuthCertChain(gatewayUrl, cert, expectedAid);

      try {
        await this._verifyAuthCertRevocation(gatewayUrl, cert, expectedAid);
      } catch (e) {
        const errMsg = e instanceof Error ? e.message : String(e);
        if (/revoked/i.test(errMsg)) throw e instanceof AuthError ? e : new AuthError(errMsg);
        this._logger.warn(`CRL verification unavailable, skipping: ${errMsg}`);
      }

      try {
        await this._verifyAuthCertOcsp(gatewayUrl, cert, expectedAid);
      } catch (exc) {
        const errMsg = exc instanceof Error ? exc.message : String(exc);
        if (/revoked/i.test(errMsg)) throw exc instanceof AuthError ? exc : new AuthError(errMsg);
        this._logger.warn(`OCSP verification unavailable, skipping: ${errMsg}`);
      }

      // 检查 CN 匹配
      const cn = _certSubjectCN(cert);
      if (cn !== expectedAid) {
        throw new AuthError(`peer cert CN mismatch: expected ${expectedAid}, got ${cn || 'none'}`);
      }
      this._logger.debug(`verifyPeerCertificate exit: elapsed=${Date.now() - tStart}ms aid=${expectedAid}`);
    } catch (err) {
      this._logger.debug(`verifyPeerCertificate exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 预置 Gateway CA 链材料，但不标记为已验证。 */
  cacheGatewayCaChain(gatewayUrl: string, caChainPems: string[], chainAid: string = ''): void {
    const normalized = caChainPems
      .map((pem) => String(pem ?? '').trim())
      .filter((pem) => pem.length > 0);
    if (normalized.length === 0) return;
    for (const pem of normalized) _loadX509(pem);
    const cacheKey = chainAid ? `${gatewayUrl}:${chainAid}` : gatewayUrl;
    this._gatewayChainCache.set(cacheKey, normalized);
    this._gatewayCaVerified.delete(cacheKey);
  }

  /** 丢弃预置或缓存的 Gateway CA 链材料。 */
  discardGatewayCaChain(gatewayUrl: string, chainAid: string = ''): void {
    const cacheKey = chainAid ? `${gatewayUrl}:${chainAid}` : gatewayUrl;
    this._gatewayChainCache.delete(cacheKey);
    this._gatewayCaVerified.delete(cacheKey);
  }

  // ── 内部方法：短连接 RPC ────────────────────────────────────

  /**
   * 通过临时 WebSocket 发送单次 JSON-RPC 请求。
   * 流程：连接 → 接收 challenge → 发送请求 → 接收响应 → 关闭。
   */
  protected async _shortRpc(
    gatewayUrl: string,
    method: string,
    params: RpcParams,
  ): Promise<JsonObject> {
    this._logger.debug(`_shortRpc enter: method=${method}, gateway=${gatewayUrl}`);
    const ws = await this._connectionFactory(gatewayUrl);
    try {
      // 接收 challenge（第一条消息）
      await this._wsRecv(ws);

      // 发送 RPC 请求
      const payload = JSON.stringify({
        jsonrpc: '2.0',
        id: `pre-${method}`,
        method,
        params,
      });
      this._logger.debug(`short RPC request full: ${JSON.stringify(_redactRpcLogPayload(JSON.parse(payload)))}`);
      ws.send(payload);

      // 接收响应
      const raw = await this._wsRecv(ws);
      const message = typeof raw === 'string' ? JSON.parse(raw) : raw;
      this._logger.debug(`short RPC response full: method=${method} ${JSON.stringify(_redactRpcLogPayload(message))}`);

      if (message.error) {
        throw mapRemoteError(message.error);
      }
      const result = isJsonObject(message.result) ? message.result : null;
      if (result === null) {
        throw new ValidationError(`invalid pre-auth response for ${method}`);
      }
      if (result.success === false) {
        throw new AuthError(String(result.error || `${method} failed`), { data: result });
      }
      return result;
    } finally {
      try {
        ws.close();
      } catch {
        // 忽略关闭错误
      }
    }
  }

  /** 从 WebSocket 接收一条消息（Promise 封装） */
  private _wsRecv(ws: WebSocket): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new AuthError('websocket recv timeout'));
      }, 10000);

      const handler = (data: WebSocket.RawData) => {
        clearTimeout(timer);
        ws.off('message', handler);
        ws.off('error', errHandler);
        if (Buffer.isBuffer(data)) {
          resolve(data.toString('utf-8'));
        } else if (data instanceof ArrayBuffer) {
          resolve(Buffer.from(data).toString('utf-8'));
        } else {
          resolve(String(data));
        }
      };

      const errHandler = (err: Error) => {
        clearTimeout(timer);
        ws.off('message', handler);
        reject(new AuthError(`websocket error: ${err.message}`));
      };

      ws.on('message', handler);
      ws.on('error', errHandler);
    });
  }

  // ── 内部方法：认证流程 ──────────────────────────────────────

  /** 两阶段登录 */
  private async _login(
    gatewayUrl: string,
    identity: IdentityRecord,
  ): Promise<JsonObject> {
    const tStart = Date.now();
    const clientNonce = this._crypto.newClientNonce();
    this._logger.debug(`_login enter: aid=${identity.aid}`);

    try {
      // Phase 1: 发送 AID + 证书 + 客户端 nonce
      const phase1 = await this._shortRpc(gatewayUrl, 'auth.aid_login1', {
        aid: identity.aid,
        cert: identity.cert,
        client_nonce: clientNonce,
      });
      this._logger.debug(`login1 response recv: aid=${identity.aid}, request_id=${phase1.request_id}`);

      // 验证 Phase 1 响应（证书链 + 签名）
      await this._verifyPhase1Response(gatewayUrl, phase1, clientNonce);
      this._logger.debug(`login1 verify ok: aid=${identity.aid}`);

      // Phase 2: 用私钥签名 nonce
      const [signature, clientTime] = this._crypto.signLoginNonce(
        String(identity.private_key_pem),
        String(phase1.nonce),
      );
      this._logger.debug(`login2 start: aid=${identity.aid}`);
      const phase2 = await this._shortRpc(gatewayUrl, 'auth.aid_login2', {
        aid: identity.aid,
        request_id: phase1.request_id,
        nonce: phase1.nonce,
        client_time: clientTime,
        signature,
      });
      this._logger.debug(`_login exit: elapsed=${Date.now() - tStart}ms aid=${identity.aid}, has_token=${!!phase2.access_token || !!phase2.token}`);
      return phase2;
    } catch (err) {
      this._logger.debug(`_login exit (error): elapsed=${Date.now() - tStart}ms aid=${identity.aid} err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 刷新 access_token */
  private async _refreshAccessToken(
    gatewayUrl: string,
    refreshToken: string,
    identity?: IdentityRecord,
  ): Promise<JsonObject> {
    const tStart = Date.now();
    this._logger.debug(`_refreshAccessToken enter`);
    try {
      const params: JsonObject = {
        refresh_token: refreshToken,
        sdk_lang: AUN_SDK_LANG,
        sdk_version: AUN_SDK_VERSION,
      };
      if (identity) {
        const aid = String(identity.aid ?? '').trim();
        const deviceId = String((identity as JsonObject).device_id ?? '').trim();
        const slotId = String((identity as JsonObject).slot_id ?? '').trim();
        const accessToken = String(identity.access_token ?? '').trim();
        if (aid) params.aid = aid;
        if (deviceId) params.device_id = deviceId;
        if (slotId) params.slot_id = slotId;
        if (accessToken) params.access_token = accessToken;
        if (typeof identity.access_token_expires_at === 'number') {
          params.access_token_expires_at = identity.access_token_expires_at;
        }
      }
      const result = await this._shortRpc(gatewayUrl, 'auth.refresh_token', params);
      if (!result.success) {
        throw new AuthError(String(result.error || 'refresh failed'), { data: result });
      }
      this._logger.debug(`_refreshAccessToken exit: elapsed=${Date.now() - tStart}ms`);
      return result;
    } catch (err) {
      this._logger.debug(`_refreshAccessToken exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 会话初始化：发送 auth.connect RPC */
  private async _initializeSession(
    transport: RPCTransport,
    nonce: string,
    token: string,
    opts?: {
      deviceId?: string;
      slotId?: string;
      deliveryMode?: JsonObject | null;
      connectionKind?: string;
      shortTtlMs?: number;
      extraInfo?: Record<string, unknown>;
    },
  ): Promise<JsonObject> {
    const connectionKind = String(opts?.connectionKind ?? 'long');
    this._logger.debug(`session init start: deviceId=${opts?.deviceId ?? ''}, slotId=${opts?.slotId ?? ''}, kind=${connectionKind}`);
    const extraInfoRaw = opts?.extraInfo;
    // _capabilities 是内部覆盖字段（与 Python 对齐），默认能力声明为 V2-only
    //（supported_p2p_e2ee / supported_group_e2ee 仅包含 e2ee_v2 / group_e2ee_v2）。
    const capabilitiesOverride =
      extraInfoRaw && typeof extraInfoRaw['_capabilities'] === 'object' && extraInfoRaw['_capabilities'] !== null
        ? (extraInfoRaw['_capabilities'] as JsonObject)
        : null;
    const capabilities: JsonObject = {
      ...(capabilitiesOverride ?? {}),
      e2ee: true,
      group_e2ee: true,
      supported_p2p_e2ee: ['e2ee_v2'],
      supported_group_e2ee: ['group_e2ee_v2'],
    };
    const request: JsonObject = {
      nonce,
      auth: { method: 'kite_token', token },
      protocol: { min: '1.0', max: '1.0' },
      device: { id: String(opts?.deviceId ?? ''), type: 'sdk' },
      client: {
        slot_id: String(opts?.slotId ?? ''),
        sdk_lang: AUN_SDK_LANG,
        sdk_version: AUN_SDK_VERSION,
      },
      delivery_mode: opts?.deliveryMode ?? { mode: 'fanout' },
      capabilities,
    };
    // extra_info：应用层自定义信息（PID/HOME/备注等），踢人时透传给被踢方
    // _capabilities 是内部覆盖字段，不透传到服务端
    if (extraInfoRaw) {
      const filtered: JsonObject = {};
      for (const [k, v] of Object.entries(extraInfoRaw)) {
        if (!k.startsWith('_')) filtered[k] = v as JsonObject[string];
      }
      if (Object.keys(filtered).length > 0) {
        request.extra_info = filtered;
      }
    }
    // 长短连接选项：默认 long 时不写入 options（保持 wire 兼容）
    if (connectionKind === 'short') {
      const options: JsonObject = { kind: 'short' };
      const ttl = Number(opts?.shortTtlMs ?? 0);
      if (ttl > 0) {
        options.short_ttl_ms = ttl;
      }
      request.options = options;
    }
    const result = await transport.call('auth.connect', request as RpcParams);

    const status = isJsonObject(result) ? result.status : undefined;
    if (status !== 'ok') {
      this._logger.error(`sessioninitfailed: status=${status}, result=${JSON.stringify(result)}`);
      throw new AuthError(`initialize failed: ${JSON.stringify(result)}`);
    }
    this._logger.debug('sessioninitok');
    return isJsonObject(result) ? (result as JsonObject) : ({} as JsonObject);
  }

  // ── 内部方法：证书验证 ──────────────────────────────────────

  /**
   * 验证 Phase 1 响应：
   * 1. 解析 auth_cert
   * 2. 验证证书链 + CRL + OCSP
   * 3. 验证 client_nonce_signature
   */
  private async _verifyPhase1Response(
    gatewayUrl: string,
    result: JsonObject,
    clientNonce: string,
  ): Promise<void> {
    const authCertPem = String(result.auth_cert || '');
    const signatureB64 = String(result.client_nonce_signature || '');

    if (!authCertPem) {
      throw new AuthError('aid_login1 missing auth_cert');
    }
    if (!signatureB64) {
      throw new AuthError('aid_login1 missing client_nonce_signature');
    }

    let authCert: crypto.X509Certificate;
    try {
      authCert = _loadX509(authCertPem);
    } catch {
      throw new AuthError('aid_login1 returned invalid auth_cert');
    }

    // 验证证书链、CRL、OCSP
    await this._verifyAuthCertChain(gatewayUrl, authCert);
    try {
      await this._verifyAuthCertRevocation(gatewayUrl, authCert);
    } catch (e) {
      const errMsg = e instanceof Error ? e.message : String(e);
      if (/revoked/i.test(errMsg)) throw e instanceof AuthError ? e : new AuthError(errMsg);
      this._logger.warn(`CRL verification unavailable, skipping: ${errMsg}`);
    }
    try {
      await this._verifyAuthCertOcsp(gatewayUrl, authCert);
    } catch (exc) {
      const errMsg = exc instanceof Error ? exc.message : String(exc);
      if (/revoked/i.test(errMsg)) throw exc instanceof AuthError ? exc : new AuthError(errMsg);
      this._logger.warn(`OCSP verification unavailable, skipping: ${errMsg}`);
    }

    // 验证 client_nonce 签名
    try {
      const signature = Buffer.from(signatureB64, 'base64');
      const pubKey = _extractPublicKey(authCert);
      _verifySignature(pubKey, signature, Buffer.from(clientNonce, 'utf-8'));
    } catch (e) {
      if (e instanceof AuthError && e.message.includes('signature verification failed')) {
        throw new AuthError('aid_login1 server auth signature verification failed');
      }
      throw new AuthError('aid_login1 server auth signature verification failed');
    }
  }

  /**
   * 验证认证证书链。
   * 1. 检查缓存
   * 2. 时间有效性
   * 3. 签名链验证
   * 4. BasicConstraints 检查
   * 5. 根证书自签 + 受信根锚定
   */
  private async _verifyAuthCertChain(
    gatewayUrl: string,
    authCert: crypto.X509Certificate,
    chainAid: string = '',
  ): Promise<void> {
    const certSerial = _certSerialHex(authCert);

    // 检查缓存
    const cachedAt = this._chainVerifiedCache.get(certSerial);
    if (cachedAt && Date.now() - cachedAt < this._chainCacheTtl) {
      return;
    }

    const nowMs = Date.now();
    _ensureCertTimeValid(authCert, 'auth certificate', nowMs);

    const chain = await this._loadGatewayCaChain(gatewayUrl, chainAid);
    if (!chain.length) {
      throw new AuthError('unable to verify auth certificate chain: missing CA chain');
    }

    const cacheKey = chainAid ? `${gatewayUrl}:${chainAid}` : gatewayUrl;

    // 快速路径：CA 链已通过完整验证
    if (this._gatewayCaVerified.get(cacheKey)) {
      const issuer = chain[0];
      _ensureCertTimeValid(issuer, 'Issuer CA', nowMs);
      if (!_isCaCert(issuer)) {
        throw new AuthError('Issuer CA is not marked as CA (fast path)');
      }
      if (!_checkIssuedBy(authCert, issuer)) {
        throw new AuthError('auth certificate issuer mismatch');
      }
      if (!_verifyCertSignedBy(authCert, issuer)) {
        throw new AuthError('auth certificate signature verification failed');
      }
      this._chainVerifiedCache.set(certSerial, Date.now());
      return;
    }

    // 首次验证：完整验证流程
    let current = authCert;
    for (let i = 0; i < chain.length; i++) {
      const caCert = chain[i];
      _ensureCertTimeValid(caCert, `CA certificate[${i}]`, nowMs);
      if (!_checkIssuedBy(current, caCert)) {
        throw new AuthError(`auth certificate issuer mismatch at chain level ${i}`);
      }
      if (!_verifyCertSignedBy(current, caCert)) {
        throw new AuthError(`auth certificate signature verification failed at chain level ${i}`);
      }
      if (!_isCaCert(caCert)) {
        throw new AuthError(`CA certificate[${i}] is not marked as CA`);
      }
      current = caCert;
    }

    // 验证根证书自签
    const root = chain[chain.length - 1];
    if (!_isSelfSigned(root)) {
      throw new AuthError('auth certificate chain root is not self-signed');
    }
    if (!_verifyCertSignedBy(root, root)) {
      throw new AuthError('auth certificate chain root self-signature verification failed');
    }

    // 验证根证书在受信列表中
    const trustedRoots = this._loadTrustedRoots();
    const rootDer = _certDer(root);
    const isTrusted = trustedRoots.some((tr) => _certDer(tr).equals(rootDer));
    if (!isTrusted) {
      throw new AuthError('auth certificate chain is not anchored by a trusted root');
    }

    // 验证成功，更新缓存
    this._chainVerifiedCache.set(certSerial, Date.now());
    this._gatewayCaVerified.set(cacheKey, true);
  }

  /** 加载 Gateway CA 链（带缓存） */
  private async _loadGatewayCaChain(
    gatewayUrl: string,
    chainAid: string = '',
  ): Promise<crypto.X509Certificate[]> {
    const cacheKey = chainAid ? `${gatewayUrl}:${chainAid}` : gatewayUrl;
    let cached = this._gatewayChainCache.get(cacheKey);
    if (!cached) {
      cached = await this._fetchGatewayCaChain(gatewayUrl, chainAid);
      this._gatewayChainCache.set(cacheKey, cached);
    }
    return cached.map((pem) => _loadX509(pem));
  }

  /** 从 Gateway PKI 端点获取 CA 链 */
  private async _fetchGatewayCaChain(
    gatewayUrl: string,
    _chainAid: string = '',
  ): Promise<string[]> {
    const url = _gatewayHttpUrl(gatewayUrl, '/pki/chain');
    const text = await _fetchText(url, this._verifySsl, this._net);
    return _splitPemBundle(text);
  }

  /**
   * CRL 吊销检查。
   * 从 Gateway 的 /pki/crl.json 端点获取 CRL，
   * 验证签发者签名，检查证书序列号是否在吊销列表中。
   */
  private async _verifyAuthCertRevocation(
    gatewayUrl: string,
    authCert: crypto.X509Certificate,
    chainAid: string = '',
  ): Promise<void> {
    const chain = await this._loadGatewayCaChain(gatewayUrl, chainAid);
    if (!chain.length) {
      throw new AuthError('unable to verify auth certificate revocation: missing issuer certificate');
    }

    // 跨域时：CRL 请求发到 peer 所在域的 Gateway
    let crlGatewayUrl = gatewayUrl;
    if (chainAid && chainAid.includes('.')) {
      const peerIssuer = chainAid.split('.').slice(1).join('.');
      const localMatch = gatewayUrl.match(/gateway\.([^:/]+)/);
      const localIssuer = localMatch ? localMatch[1] : '';
      if (localIssuer && peerIssuer !== localIssuer) {
        crlGatewayUrl = gatewayUrl.replace(`gateway.${localIssuer}`, `gateway.${peerIssuer}`);
      }
    }

    const revokedSerials = await this._loadGatewayRevokedSerials(crlGatewayUrl, chain[0]);
    const serialHex = _certSerialHex(authCert);
    if (revokedSerials.has(serialHex)) {
      throw new AuthError('auth certificate has been revoked');
    }
  }

  /** 加载 Gateway 吊销列表（带缓存） */
  private async _loadGatewayRevokedSerials(
    gatewayUrl: string,
    issuerCert: crypto.X509Certificate,
  ): Promise<Set<string>> {
    const cached = this._gatewayCrlCache.get(gatewayUrl);
    const now = Date.now();
    if (cached && cached.nextRefreshAt > now) {
      return cached.revokedSerials;
    }
    const entry = await this._fetchGatewayCrl(gatewayUrl, issuerCert);
    this._gatewayCrlCache.set(gatewayUrl, entry);
    return entry.revokedSerials;
  }

  /**
   * 从 Gateway /pki/crl.json 获取 CRL 并解析。
   *
   * 响应格式: { crl_pem: "...", revoked_serials?: [...] }
   *
   * 注意：完整的 CRL PEM 签名验证需要 ASN.1/DER 解析，
   * Node.js 标准库不直接支持 CRL 解析。
   * 这里使用 JSON 响应中的 revoked_serials 字段作为可信数据源，
   * 并验证 crl_pem 存在性。完整的 CRL 签名验证需要依赖
   * @peculiar/x509 或手动 ASN.1 解析。
   */
  private async _fetchGatewayCrl(
    gatewayUrl: string,
    _issuerCert: crypto.X509Certificate,
  ): Promise<CrlCacheEntry> {
    const url = _gatewayHttpUrl(gatewayUrl, '/pki/crl.json');
    const payload = await _fetchJson(url, this._verifySsl, this._net);
    const crlPem = String(payload.crl_pem || '');
    if (!crlPem) {
      throw new AuthError('gateway CRL endpoint returned no signed CRL');
    }

    // 从 JSON 响应中提取吊销序列号列表
    // Gateway 的 crl.json 同时包含 crl_pem（签名 CRL）和 revoked_serials（方便客户端解析）
    let revokedSerials = new Set<string>();

    // 尝试解析 CRL PEM 以提取吊销序列号
    // Node.js 不直接支持 CRL 解析，尝试从 DER 中手动提取
    try {
      revokedSerials = this._parseCrlRevokedSerials(crlPem, _issuerCert);
    } catch {
      // CRL 解析失败时，降级使用 JSON 响应中的 revoked_serials（如果提供）
      const serialsArr = payload.revoked_serials;
      if (Array.isArray(serialsArr)) {
        revokedSerials = new Set(serialsArr.map((s) => String(s).toLowerCase()));
      }
      // 如果两者都没有，返回空集合（无吊销记录）
      this._logger.debug('CRL PEM parse failed, using JSON revoked_serials fallback');
    }

    // 缓存 TTL：默认 5 分钟，最大 24 小时
    const now = Date.now();
    let nextRefreshAt = now + 300_000; // 5 分钟
    const maxRefreshAt = now + 86400_000; // 24 小时
    nextRefreshAt = Math.min(nextRefreshAt, maxRefreshAt);

    return { revokedSerials, nextRefreshAt };
  }

  /**
   * 从 CRL PEM 解析吊销序列号。
   * 简化的 ASN.1 DER 解析：提取 TBSCertList 中的 revokedCertificates 序列号。
   *
   * CRL ASN.1 结构（简化）：
   * CertificateList ::= SEQUENCE {
   *   tbsCertList    TBSCertList,
   *   signatureAlgorithm AlgorithmIdentifier,
   *   signature      BIT STRING
   * }
   *
   * TBSCertList ::= SEQUENCE {
   *   version              INTEGER OPTIONAL,
   *   signature            AlgorithmIdentifier,
   *   issuer               Name,
   *   thisUpdate           Time,
   *   nextUpdate           Time OPTIONAL,
   *   revokedCertificates  SEQUENCE OF SEQUENCE { ... } OPTIONAL,
   *   ...
   * }
   */
  private _parseCrlRevokedSerials(
    crlPem: string,
    issuerCert: crypto.X509Certificate,
  ): Set<string> {
    // 提取 DER 数据
    const b64 = crlPem
      .replace(/-----BEGIN X509 CRL-----/g, '')
      .replace(/-----END X509 CRL-----/g, '')
      .replace(/\s/g, '');
    const der = Buffer.from(b64, 'base64');

    // 简化 ASN.1 解析：提取 TBSCertList 和签名
    // 外层 SEQUENCE
    const outer = this._readAsn1Sequence(der, 0);
    if (!outer) throw new Error('invalid CRL: not a SEQUENCE');

    // TBSCertList SEQUENCE
    const tbsStart = outer.contentOffset;
    const tbs = this._readAsn1Sequence(der, tbsStart);
    if (!tbs) throw new Error('invalid CRL: TBSCertList not a SEQUENCE');

    // 验证签发者签名
    const tbsBytes = der.subarray(tbsStart, tbsStart + tbs.totalLength);
    // 签名在 TBSCertList 之后：先跳过 AlgorithmIdentifier，再读取 BIT STRING
    let sigOffset = tbsStart + tbs.totalLength;
    // 跳过 signatureAlgorithm SEQUENCE
    const sigAlg = this._readAsn1Tag(der, sigOffset);
    if (sigAlg) sigOffset += sigAlg.totalLength;
    // 读取 signature BIT STRING
    const sigBitString = this._readAsn1Tag(der, sigOffset);
    if (sigBitString && der[sigOffset] === 0x03) {
      // BIT STRING 第一个字节是 padding bits 数（通常为 0）
      const sigBytes = der.subarray(
        sigBitString.contentOffset + 1,
        sigBitString.contentOffset + sigBitString.contentLength,
      );
      try {
        const pubKey = _extractPublicKey(issuerCert);
        _verifySignature(pubKey, Buffer.from(sigBytes), Buffer.from(tbsBytes));
      } catch {
        throw new AuthError('gateway CRL signature verification failed');
      }
    }

    // 解析 TBSCertList 内部字段以找到 revokedCertificates
    const revokedSerials = new Set<string>();
    let offset = tbs.contentOffset;
    const tbsEnd = tbs.contentOffset + tbs.contentLength;
    let fieldIdx = 0;

    while (offset < tbsEnd) {
      const tag = this._readAsn1Tag(der, offset);
      if (!tag) break;

      // revokedCertificates 是 TBSCertList 中的第 6 个字段（index 5，version 从 0 开始）
      // 或者根据 tag 判断：它是一个 SEQUENCE OF SEQUENCE
      // 实际上字段顺序为：version?, signatureAlg, issuer, thisUpdate, nextUpdate?, revokedCerts?
      // 简化方式：找到包含 INTEGER（序列号）的嵌套 SEQUENCE 结构
      if (fieldIdx >= 4 && der[offset] === 0x30) {
        // 这可能是 revokedCertificates SEQUENCE OF
        const revokedSeq = this._readAsn1Sequence(der, offset);
        if (revokedSeq) {
          let rOffset = revokedSeq.contentOffset;
          const rEnd = revokedSeq.contentOffset + revokedSeq.contentLength;
          while (rOffset < rEnd) {
            // 每个条目是 SEQUENCE { serialNumber INTEGER, ... }
            const entry = this._readAsn1Sequence(der, rOffset);
            if (!entry) break;
            // 条目的第一个元素是 INTEGER（序列号）
            const serialTag = this._readAsn1Tag(der, entry.contentOffset);
            if (serialTag && der[entry.contentOffset] === 0x02) {
              const serialBytes = der.subarray(
                serialTag.contentOffset,
                serialTag.contentOffset + serialTag.contentLength,
              );
              const serialHex = Buffer.from(serialBytes).toString('hex').toLowerCase();
              // 去掉前导零
              const cleaned = serialHex.replace(/^0+/, '') || '0';
              revokedSerials.add(cleaned);
            }
            rOffset += entry.totalLength;
          }
          break; // 找到 revokedCertificates 后退出
        }
      }

      offset += tag.totalLength;
      fieldIdx++;
    }

    return revokedSerials;
  }

  /**
   * OCSP 状态检查。
   * 从 Gateway 的 /pki/ocsp/{serial_hex} 端点获取 OCSP 响应。
   */
  private async _verifyAuthCertOcsp(
    gatewayUrl: string,
    authCert: crypto.X509Certificate,
    chainAid: string = '',
  ): Promise<void> {
    const chain = await this._loadGatewayCaChain(gatewayUrl, chainAid);
    if (!chain.length) {
      throw new AuthError('unable to verify auth certificate OCSP status: missing issuer certificate');
    }
    const status = await this._loadGatewayOcspStatus(gatewayUrl, authCert, chain[0]);
    if (status === 'revoked') {
      throw new AuthError('auth certificate OCSP status is revoked');
    }
    if (status !== 'good') {
      throw new AuthError(`auth certificate OCSP status is ${status}`);
    }
  }

  /** 加载 Gateway OCSP 状态（带缓存） */
  private async _loadGatewayOcspStatus(
    gatewayUrl: string,
    authCert: crypto.X509Certificate,
    issuerCert: crypto.X509Certificate,
  ): Promise<string> {
    const serialHex = _certSerialHex(authCert);
    let gatewayCache = this._gatewayOcspCache.get(gatewayUrl);
    if (!gatewayCache) {
      gatewayCache = new Map();
      this._gatewayOcspCache.set(gatewayUrl, gatewayCache);
    }
    const cached = gatewayCache.get(serialHex);
    const now = Date.now();
    if (cached && cached.nextRefreshAt > now) {
      return cached.status;
    }
    const entry = await this._fetchGatewayOcspStatus(gatewayUrl, authCert, issuerCert);
    gatewayCache.set(serialHex, entry);
    return entry.status;
  }

  /**
   * 从 Gateway /pki/ocsp/{serial_hex} 获取 OCSP 状态。
   *
   * 响应格式: { status: "good"|"revoked"|"unknown", ocsp_response: "base64..." }
   *
   * 注意：完整的 OCSP DER 响应解析需要 ASN.1 解析。
   * 这里从 JSON 响应中提取 status 字段，并验证 ocsp_response 存在性。
   * 对于 ocsp_response 的签名验证，实现简化的 DER 解析以提取关键字段。
   */
  private async _fetchGatewayOcspStatus(
    gatewayUrl: string,
    authCert: crypto.X509Certificate,
    issuerCert: crypto.X509Certificate,
  ): Promise<OcspCacheEntry> {
    const serialHex = _certSerialHex(authCert);
    const url = _gatewayHttpUrl(gatewayUrl, `/pki/ocsp/${serialHex}`);
    const payload = await _fetchJson(url, this._verifySsl, this._net);
    const status = String(payload.status || '');
    const ocspB64 = String(payload.ocsp_response || '');

    if (!ocspB64) {
      throw new AuthError('gateway OCSP endpoint returned no ocsp_response');
    }

    let effectiveStatus: string;

    try {
      // 尝试解析 DER OCSP 响应
      const ocspDer = Buffer.from(ocspB64, 'base64');
      effectiveStatus = this._parseOcspResponse(ocspDer, authCert, issuerCert);
    } catch (e) {
      // OCSP DER 解析失败时，降级信赖 JSON status 字段
      if (e instanceof AuthError) throw e;
      this._logger.debug(`OCSP DER parse failed, using JSON status fallback: ${e instanceof Error ? e.message : String(e)}`);
      if (!status) {
        throw new AuthError('gateway OCSP endpoint returned invalid response and no status field');
      }
      effectiveStatus = status;
    }

    // 如果 JSON status 和 DER 解析结果不一致则报错
    if (status && status !== effectiveStatus) {
      throw new AuthError('gateway OCSP status mismatch');
    }

    // 缓存 TTL：默认 5 分钟，最大 24 小时
    const now = Date.now();
    const nextRefreshAt = Math.min(now + 300_000, now + 86400_000);

    return { status: effectiveStatus, nextRefreshAt };
  }

  /**
   * 简化的 OCSP DER 响应解析。
   *
   * OCSPResponse ::= SEQUENCE {
   *   responseStatus  ENUMERATED { successful(0), ... },
   *   responseBytes   [0] EXPLICIT SEQUENCE {
   *     responseType   OID,
   *     response       OCTET STRING (BasicOCSPResponse DER)
   *   } OPTIONAL
   * }
   *
   * BasicOCSPResponse ::= SEQUENCE {
   *   tbsResponseData  ResponseData,
   *   signatureAlgorithm AlgorithmIdentifier,
   *   signature        BIT STRING,
   *   ...
   * }
   *
   * ResponseData ::= SEQUENCE {
   *   version          [0] EXPLICIT INTEGER DEFAULT v1,
   *   responderID      ...,
   *   producedAt       GeneralizedTime,
   *   responses        SEQUENCE OF SingleResponse,
   *   ...
   * }
   *
   * SingleResponse ::= SEQUENCE {
   *   certID           CertID,
   *   certStatus       CHOICE { good [0], revoked [1], unknown [2] },
   *   thisUpdate       GeneralizedTime,
   *   nextUpdate       [0] EXPLICIT GeneralizedTime OPTIONAL,
   * }
   *
   * 这里只做关键字段提取：responseStatus、certStatus。
   * 完整签名验证依赖更全面的 ASN.1 库。
   */
  private _parseOcspResponse(
    ocspDer: Buffer,
    _authCert: crypto.X509Certificate,
    _issuerCert: crypto.X509Certificate,
  ): string {
    // 外层 SEQUENCE
    const outer = this._readAsn1Sequence(ocspDer, 0);
    if (!outer) throw new Error('invalid OCSP response: not a SEQUENCE');

    // responseStatus ENUMERATED
    let offset = outer.contentOffset;
    const statusTag = this._readAsn1Tag(ocspDer, offset);
    if (!statusTag || ocspDer[offset] !== 0x0a) {
      throw new Error('invalid OCSP response: missing responseStatus');
    }
    const responseStatus = ocspDer[statusTag.contentOffset];
    if (responseStatus !== 0) {
      // 非 successful（如 unauthorized=6 表示 responder 无法回答，常见于 unknown 证书）
      // 抛普通 Error 而非 AuthError，让外层 catch 降级到 JSON status 字段
      const statusNames = ['successful', 'malformedRequest', 'internalError', 'tryLater', '', 'sigRequired', 'unauthorized'];
      const statusName = statusNames[responseStatus] || `unknown(${responseStatus})`;
      throw new Error(`OCSP responseStatus is ${statusName} (non-successful), fallback to JSON status`);
    }
    offset += statusTag.totalLength;

    // responseBytes [0] EXPLICIT
    if (offset >= outer.contentOffset + outer.contentLength) {
      throw new Error('invalid OCSP response: missing responseBytes');
    }
    const respBytesTag = this._readAsn1Tag(ocspDer, offset);
    if (!respBytesTag) throw new Error('invalid OCSP response: cannot read responseBytes');

    // 内部 SEQUENCE { responseType OID, response OCTET STRING }
    const respBytesSeq = this._readAsn1Sequence(ocspDer, respBytesTag.contentOffset);
    if (!respBytesSeq) throw new Error('invalid OCSP response: responseBytes not a SEQUENCE');

    // 跳过 responseType OID
    let innerOffset = respBytesSeq.contentOffset;
    const oidTag = this._readAsn1Tag(ocspDer, innerOffset);
    if (!oidTag) throw new Error('invalid OCSP response: missing responseType OID');
    innerOffset += oidTag.totalLength;

    // response OCTET STRING (包含 BasicOCSPResponse DER)
    const octetTag = this._readAsn1Tag(ocspDer, innerOffset);
    if (!octetTag || ocspDer[innerOffset] !== 0x04) {
      throw new Error('invalid OCSP response: missing response OCTET STRING');
    }
    const basicDer = ocspDer.subarray(octetTag.contentOffset, octetTag.contentOffset + octetTag.contentLength);

    // BasicOCSPResponse SEQUENCE
    const basicSeq = this._readAsn1Sequence(basicDer, 0);
    if (!basicSeq) throw new Error('invalid OCSP response: BasicOCSPResponse not a SEQUENCE');

    // tbsResponseData SEQUENCE
    const tbsSeq = this._readAsn1Sequence(basicDer, basicSeq.contentOffset);
    if (!tbsSeq) throw new Error('invalid OCSP response: tbsResponseData not a SEQUENCE');

    // 解析 tbsResponseData 以找到 responses
    // 字段顺序：version?, responderID, producedAt, responses, extensions?
    let tbsOffset = tbsSeq.contentOffset;
    const tbsEnd = tbsSeq.contentOffset + tbsSeq.contentLength;

    // 跳过 version [0] EXPLICIT（如果存在）
    // 只能精确匹配 0xa0，不能用“任意 context-specific constructed tag”判断；
    // responderID 也可能是 [2] / 0xa2，误判会把后续字段整体错位。
    if (tbsOffset < tbsEnd && basicDer[tbsOffset] === 0xa0) {
      const versionTag = this._readAsn1Tag(basicDer, tbsOffset);
      if (versionTag) tbsOffset += versionTag.totalLength;
    }

    // 跳过 responderID (CHOICE)
    if (tbsOffset < tbsEnd) {
      const respIdTag = this._readAsn1Tag(basicDer, tbsOffset);
      if (respIdTag) tbsOffset += respIdTag.totalLength;
    }

    // 跳过 producedAt GeneralizedTime
    if (tbsOffset < tbsEnd) {
      const prodAtTag = this._readAsn1Tag(basicDer, tbsOffset);
      if (prodAtTag) tbsOffset += prodAtTag.totalLength;
    }

    // responses SEQUENCE OF SingleResponse
    if (tbsOffset >= tbsEnd) throw new Error('invalid OCSP response: missing responses');
    const responsesSeq = this._readAsn1Sequence(basicDer, tbsOffset);
    if (!responsesSeq) throw new Error('invalid OCSP response: responses not a SEQUENCE');

    // 解析第一个 SingleResponse
    const singleSeq = this._readAsn1Sequence(basicDer, responsesSeq.contentOffset);
    if (!singleSeq) throw new Error('invalid OCSP response: SingleResponse not a SEQUENCE');

    // SingleResponse: { certID SEQUENCE, certStatus CHOICE, thisUpdate, nextUpdate? }
    let srOffset = singleSeq.contentOffset;

    // 跳过 certID SEQUENCE
    const certIdTag = this._readAsn1Tag(basicDer, srOffset);
    if (!certIdTag) throw new Error('invalid OCSP response: missing certID');
    srOffset += certIdTag.totalLength;

    // certStatus CHOICE: good [0] IMPLICIT NULL, revoked [1] IMPLICIT ..., unknown [2] IMPLICIT NULL
    if (srOffset >= singleSeq.contentOffset + singleSeq.contentLength) {
      throw new Error('invalid OCSP response: missing certStatus');
    }
    const certStatusByte = basicDer[srOffset];
    // context-specific tag class (bits 7-6 = 10), constructed bit (bit 5)
    const tagNumber = certStatusByte & 0x1f;

    if (tagNumber === 0) return 'good';
    if (tagNumber === 1) return 'revoked';
    if (tagNumber === 2) return 'unknown';

    return 'unknown';
  }

  // ── ASN.1 DER 辅助解析 ─────────────────────────────────────

  /** 读取 ASN.1 SEQUENCE 标签，返回内容偏移和长度 */
  private _readAsn1Sequence(
    buf: Buffer,
    offset: number,
  ): { contentOffset: number; contentLength: number; totalLength: number } | null {
    if (offset >= buf.length) return null;
    const tag = buf[offset];
    // SEQUENCE 或 CONSTRUCTED SEQUENCE (0x30)
    if (tag !== 0x30) {
      // 也接受 context-specific constructed tags
      if ((tag & 0x20) === 0) return null;
    }
    return this._readAsn1Tag(buf, offset);
  }

  /** 读取任意 ASN.1 标签的长度信息 */
  private _readAsn1Tag(
    buf: Buffer,
    offset: number,
  ): { contentOffset: number; contentLength: number; totalLength: number } | null {
    if (offset >= buf.length) return null;
    let pos = offset + 1; // 跳过 tag byte
    if (pos >= buf.length) return null;

    // 读取长度
    const firstLenByte = buf[pos];
    let contentLength: number;
    let lenBytes: number;

    if (firstLenByte < 0x80) {
      // 短格式
      contentLength = firstLenByte;
      lenBytes = 1;
    } else if (firstLenByte === 0x80) {
      // 不定长格式（不支持）
      return null;
    } else {
      // 长格式
      const numLenBytes = firstLenByte & 0x7f;
      if (pos + numLenBytes >= buf.length) return null;
      contentLength = 0;
      for (let i = 0; i < numLenBytes; i++) {
        contentLength = (contentLength << 8) | buf[pos + 1 + i];
      }
      lenBytes = 1 + numLenBytes;
    }

    const contentOffset = offset + 1 + lenBytes;
    const totalLength = 1 + lenBytes + contentLength;

    return { contentOffset, contentLength, totalLength };
  }

  // ── 内部方法：证书恢复 ─────────────────────────────────────

  /**
   * 从 PKI HTTP 端点下载证书恢复。
   * 本地有密钥但无证书、服务端已注册时使用。
   */
  private async _recoverCertViaDownload(
    gatewayUrl: string,
    identity: IdentityRecord,
  ): Promise<IdentityRecord> {
    const certPem = await this._downloadRegisteredCert(gatewayUrl, String(identity.aid));
    if (!certPem) {
      throw new AuthError(`failed to download certificate for ${identity.aid}`);
    }

    // 验证下载的证书公钥与本地密钥对匹配
    const cert = _loadX509(certPem);
    const certPubKey = _extractPublicKey(cert);
    const certPubDer = certPubKey.export({ type: 'spki', format: 'der' });
    const localPubDer = Buffer.from(String(identity.public_key_der_b64), 'base64');

    if (!certPubDer.equals(localPubDer)) {
      throw new AuthError(
        `downloaded certificate public key does not match local key pair for ${identity.aid}. ` +
        `The server has a different key registered — this AID cannot be recovered with the current key.`,
      );
    }

    identity.cert = certPem;
    return identity;
  }

  /**
   * 验证本地身份是否适合复用 cached token（不走网络）。
   * 返回空字符串表示通过；非空字符串表示不通过的原因。
   * 公钥不匹配时直接抛 AuthError（严重安全问题，不能静默降级）。
   */
  private _validateCachedCredentials(identity: IdentityRecord): string {
    const aid = identity.aid ?? '?';
    const certPem = identity.cert as string | undefined;
    const localPubB64 = identity.public_key_der_b64 as string | undefined;
    if (!certPem) return 'no certificate';
    if (!localPubB64) return 'no public key';
    try {
      const cert = _loadX509(certPem);
      const certPubKey = _extractPublicKey(cert);
      const certPubDer = certPubKey.export({ type: 'spki', format: 'der' });
      const localPubDer = Buffer.from(localPubB64, 'base64');
      if (!certPubDer.equals(localPubDer)) {
        throw new AuthError(
          `local certificate public key does not match local keypair for aid ${aid}; ` +
          `refusing to authenticate. Run auth.registerAid() to repair identity.`,
        );
      }
      // cert 时间窗口
      const now = Date.now();
      const validFrom = new Date(cert.validFrom).getTime();
      const validTo = new Date(cert.validTo).getTime();
      if (now < validFrom) return 'cert not yet valid';
      if (now > validTo) return 'cert expired';
      return '';
    } catch (e) {
      if (e instanceof AuthError) throw e;
      return `cert/keypair parse error: ${e instanceof Error ? e.message : String(e)}`;
    }
  }

  /**
   * 防线 B：authenticate 在调 _login 前显式校验 cert 与本地 keypair 公钥一致。
   * 命中即抛 AuthError，绝不发起两步登录。
   */
  protected _assertCertMatchesLocalKeypair(identity: IdentityRecord): void {
    const aid = identity.aid ?? '?';
    const certPem = identity.cert as string | undefined;
    const localPubB64 = identity.public_key_der_b64 as string | undefined;
    if (!certPem || !localPubB64) {
      throw new AuthError(
        `identity for aid ${aid} missing cert or public key; refusing to start two-phase login`,
      );
    }
    let certPubDer: Buffer;
    let localPubDer: Buffer;
    try {
      const cert = _loadX509(certPem);
      const certPubKey = _extractPublicKey(cert);
      certPubDer = certPubKey.export({ type: 'spki', format: 'der' });
      localPubDer = Buffer.from(localPubB64, 'base64');
    } catch (e) {
      throw new AuthError(
        `failed to parse local cert/keypair for aid ${aid}: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
    if (!certPubDer.equals(localPubDer)) {
      throw new AuthError(
        `local certificate public key does not match local keypair for aid ${aid}; ` +
        `refusing to start two-phase login. Run auth.registerAid() to repair identity.`,
      );
    }
  }

  /**
   * 从服务端下载指定 AID 的证书（公开 API）。
   *
   * @param gatewayUrl - Gateway WebSocket URL
   * @param aid - 目标 AID
   * @returns 证书 PEM 字符串，如果 AID 未注册则返回 null
   * @throws {AuthError} 网络错误或服务端错误
   *
   * @example
   * ```typescript
   * const cert = await auth.fetchPeerCert('wss://gateway.example.com', 'alice.aid.com');
   * if (cert) {
   *   console.log('Alice is registered');
   * }
   * ```
   */
  async fetchPeerCert(gatewayUrl: string, aid: string): Promise<string | null> {
    return this._downloadRegisteredCert(gatewayUrl, aid);
  }

  /**
   * 通过 PKI HTTP 端点下载服务端登记的证书（内部实现）。
   * 404 / 找不到 → 返回 null（视为未注册）；其它 HTTP 错抛 AuthError。
   * 该方法既用于 recover 路径，也用于 registerAid 全新注册前的查重前置。
   */
  protected async _downloadRegisteredCert(
    gatewayUrl: string,
    aid: string,
  ): Promise<string | null> {
    const certUrl = _gatewayHttpUrl(gatewayUrl, `/pki/cert/${aid}`);
    try {
      const certPem = await _fetchText(certUrl, this._verifySsl);
      if (!certPem || !certPem.includes('BEGIN CERTIFICATE')) {
        return null;
      }
      return certPem;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes('404') || msg.toLowerCase().includes('not found')) {
        return null;
      }
      throw new AuthError(`failed to fetch ${certUrl}: ${msg}`);
    }
  }

  // ── 内部方法：new_cert 验证 ────────────────────────────────

  /**
   * 验证服务端返回的 new_cert，通过后才正式接受。
   * 安全要点：CN/公钥/时间 + 完整链验证 + 受信根锚定 + CRL/OCSP。
   */
  private async _validateNewCert(
    identity: IdentityRecord,
    gatewayUrl: string = '',
  ): Promise<void> {
    const newCertPem = identity._pending_new_cert;
    delete identity._pending_new_cert;

    if (!newCertPem) return;

    try {
      const certPemStr = typeof newCertPem === 'string' ? newCertPem : String(newCertPem);
      const cert = _loadX509(certPemStr);
      const aid = String(identity.aid || '');

      // 1. CN 必须匹配当前 AID
      const cn = _certSubjectCN(cert);
      if (cn !== aid) {
        throw new AuthError(
          `new_cert CN mismatch: expected ${aid}, got ${cn || 'none'}`,
        );
      }

      // 2. 公钥必须匹配本地私钥
      const certPubKey = _extractPublicKey(cert);
      const certPubDer = certPubKey.export({ type: 'spki', format: 'der' });
      const localPubB64 = String(identity.public_key_der_b64 || '');
      if (localPubB64) {
        const localPubDer = Buffer.from(localPubB64, 'base64');
        if (!certPubDer.equals(localPubDer)) {
          throw new AuthError('new_cert public key does not match local identity key');
        }
      }

      // 3. 时间有效性
      _ensureCertTimeValid(cert, 'new_cert', Date.now());

      // 4. 完整证书链验证 + 受信根锚定 + CRL/OCSP
      if (gatewayUrl) {
        await this._verifyAuthCertChain(gatewayUrl, cert);
        try {
          await this._verifyAuthCertRevocation(gatewayUrl, cert);
        } catch (e) {
          const errMsg = e instanceof Error ? e.message : String(e);
          if (/revoked/i.test(errMsg)) throw e instanceof AuthError ? e : new AuthError(errMsg);
          this._logger.warn(`CRL verification unavailable, skipping: ${errMsg}`);
        }
        try {
          await this._verifyAuthCertOcsp(gatewayUrl, cert);
        } catch (exc) {
          const errMsg = exc instanceof Error ? exc.message : String(exc);
          if (/revoked/i.test(errMsg)) throw exc instanceof AuthError ? exc : new AuthError(errMsg);
          this._logger.warn(`OCSP verification unavailable, skipping: ${errMsg}`);
        }
      }

      // 验证通过，正式接受
      identity.cert = certPemStr;
    } catch (e) {
      if (e instanceof AuthError) {
        this._logger.warn(`rejected server new_cert (${identity.aid}): ${e.message}`);
      } else {
        this._logger.warn(`new_cert verification error (${identity.aid}): ${e instanceof Error ? e.message : String(e)}`);
      }
    }

    // active_cert 同步：验证公钥匹配后更新本地 cert
    const activeCertPem = identity._pending_active_cert;
    delete identity._pending_active_cert;
    if (typeof activeCertPem === 'string' && activeCertPem) {
      try {
        const actCert = _loadX509(activeCertPem);
        const actPubDer = _extractPublicKey(actCert).export({ type: 'spki', format: 'der' });
        const localPubB64 = String(identity.public_key_der_b64 || '');
        if (localPubB64) {
          const localPubDer = Buffer.from(localPubB64, 'base64');
          if (actPubDer.equals(localPubDer)) {
            identity.cert = activeCertPem;
          } else {
            this._logger.warn(`active_cert public key mismatch with local private key, rejecting sync (aid=${identity.aid})`);
          }
        }
      } catch (e) {
        this._logger.warn(`active_cert sync error (${identity.aid}): ${e instanceof Error ? e.message : String(e)}`);
      }
    }
  }

  // ── 内部方法：Token 管理 ───────────────────────────────────

  /**
   * 从认证结果中提取并保存 token 到 identity。
   * 与 Python SDK 的 _remember_tokens 对齐。
   */
  private static _rememberTokens(
    identity: IdentityRecord,
    authResult: JsonObject,
  ): void {
    const accessToken = authResult.access_token || authResult.token || authResult.kite_token;
    const refreshToken = authResult.refresh_token;
    const expiresIn = authResult.expires_in;

    if (typeof accessToken === 'string' && accessToken) identity.access_token = accessToken;
    if (typeof refreshToken === 'string' && refreshToken) identity.refresh_token = refreshToken;
    if (typeof authResult.token === 'string' && authResult.token) identity.kite_token = authResult.token;
    if (typeof expiresIn === 'number' && expiresIn > 0) {
      identity.access_token_expires_at = Math.floor(Date.now() / 1000 + expiresIn);
    } else if (typeof accessToken === 'string' && accessToken) {
      identity.access_token_expires_at = Math.floor(Date.now() / 1000 + 3600);
    }
    // 协议要求：login2 响应含 new_cert 时（证书过半自动续期），客户端必须保存
    // 先暂存到 _pending_new_cert，由 _validate_new_cert 验证后再正式接受
    const newCert = authResult.new_cert;
    if (typeof newCert === 'string' && newCert) {
      identity._pending_new_cert = newCert;
    }
    // 服务端返回 active_cert 用于同步本地 cert.pem
    const activeCert = authResult.active_cert;
    if (typeof activeCert === 'string' && activeCert) {
      identity._pending_active_cert = activeCert;
    }
  }

  private _refreshFailureRequiresRelogin(err: unknown): boolean {
    if (!(err instanceof AuthError)) return false;
    const data = err.data;
    if (isJsonObject(data)) {
      if (data.relogin_required === true) return true;
      const error = String(data.error ?? '').trim().toLowerCase();
      return ['missing refresh_token', 'invalid_or_expired_refresh_token', 'refresh not supported'].includes(error);
    }
    const message = err.message.trim().toLowerCase();
    return ['missing refresh_token', 'invalid_or_expired_refresh_token', 'refresh not supported'].includes(message);
  }

  private _clearCachedTokens(identity: IdentityRecord, reason: string = ''): void {
    const aid = String(identity.aid ?? '');
    const hadToken = Boolean(
      identity.access_token ||
      identity.refresh_token ||
      identity.kite_token ||
      identity.token ||
      identity.access_token_expires_at,
    );
    if (!hadToken) return;
    identity.access_token = '';
    identity.refresh_token = '';
    identity.kite_token = '';
    identity.token = '';
    identity.access_token_expires_at = 0;
    try {
      this._persistIdentity(identity);
      this._logger.warn(`cleared cached tokens after refresh failure: aid=${aid} reason=${reason}`);
    } catch (persistErr) {
      this._logger.warn(`failed to persist token cleanup: aid=${aid} err=${persistErr instanceof Error ? persistErr.message : String(persistErr)}`);
    }
  }

  /**
   * 获取缓存的 access_token（30 秒提前过期余量）。
   * 返回空字符串表示 token 不可用。
   */
  private static _getCachedAccessToken(identity: IdentityRecord): string {
    const accessToken = String(identity.access_token || '');
    if (!accessToken) return '';
    const expiresAt = identity.access_token_expires_at;
    if (typeof expiresAt === 'number' && expiresAt <= Date.now() / 1000 + 30) {
      return '';
    }
    return accessToken;
  }

  // ── 内部方法：身份管理 ─────────────────────────────────────

  // AID name 验证：4-64 字符，仅 [a-z0-9_-]，首字符不为 -，不以 guest 开头
  private static readonly _AID_NAME_RE = /^[a-z0-9_][a-z0-9_-]{3,63}$/;

  static _validateAidName(aid: string): void {
    const name = aid.includes('.') ? aid.split('.')[0] : aid;
    if (!AuthFlow._AID_NAME_RE.test(name)) {
      throw new ValidationError(
        `Invalid AID name '${name}': must be 4-64 characters, only [a-z0-9_-], cannot start with '-'`,
      );
    }
    if (name.startsWith('guest')) {
      throw new ValidationError("AID name must not start with 'guest'");
    }
  }

  // （_ensureLocalIdentity 已硬移除：注册和登录彻底分离，登录路径绝不再
  // 隐式生成密钥；新身份必须由应用层显式调 registerAid）

  /** 加载身份信息，不存在或半成品时抛出 StateError。
   *  优先使用调用方注入的内存私钥（_memIdentity），不从 tokenStore 解密私钥。
   */
  private _loadIdentityOrRaise(aid?: string): IdentityRecord {
    const requestedAid = aid ?? this._aid;

    // 优先路径：使用注入的内存 identity（私钥已由上层身份存储加载后传入）
    if (this._memIdentity) {
      const mem = this._memIdentity;
      if (requestedAid && String(mem.aid ?? '') !== requestedAid) {
        throw new StateError(`identity mismatch: requested ${requestedAid}, loaded ${mem.aid}`);
      }
      if (!mem.private_key_pem || !mem.public_key_der_b64) {
        throw new StateError(
          `injected identity for aid ${mem.aid} is incomplete (missing keypair)`,
        );
      }
      if (requestedAid) this._aid = requestedAid;
      return { ...mem };
    }

    if (requestedAid) {
      throw new StateError(
        `no injected identity for aid ${requestedAid}; call AUNClient.loadIdentity(aid) first`,
      );
    }
    throw new StateError('no local identity found, call AUNClient.loadIdentity(aid) first');
  }

  // （_ensureIdentity 已硬移除：注册和登录彻底分离，登录路径绝不再隐式
  // 生成密钥；调用方应改用 _loadIdentityOrRaise 获取已注册身份）

  private _loadInstanceState(aid: string): IdentityRecord | null {
    if (typeof this._tokenStore.loadInstanceState !== 'function') {
      return null;
    }
    return this._tokenStore.loadInstanceState(aid, this._deviceId, this._slotId) as IdentityRecord | null;
  }

  protected _persistIdentity(identity: IdentityRecord): void {
    const aid = String(identity.aid ?? '');
    if (!aid) {
      throw new StateError('identity missing aid');
    }

    const persisted: IdentityRecord = { ...identity };
    const instanceState: JsonObject = {};
    for (const key of AuthFlow._INSTANCE_STATE_FIELDS) {
      if (key in persisted) {
        instanceState[key] = persisted[key] as JsonValue;
        delete persisted[key];
      }
    }
    delete persisted.private_key_pem;
    delete persisted.public_key_der_b64;
    delete persisted.curve;

    if (typeof persisted.cert === 'string' && persisted.cert) {
      this._tokenStore.saveCert(aid, persisted.cert);
    }

    if (Object.keys(instanceState).length === 0 || typeof this._tokenStore.updateInstanceState !== 'function') {
      return;
    }
    this._tokenStore.updateInstanceState(aid, this._deviceId, this._slotId, (current) => {
      Object.assign(current, instanceState);
      return current;
    });
  }

  /** 从 challenge 消息中提取 nonce */
  private _extractChallengeNonce(challenge: RpcMessage | null): string {
    const params = isJsonObject(challenge?.params) ? challenge.params : {};
    const nonce = String(params.nonce || '');
    if (!nonce) {
      throw new AuthError('gateway challenge missing nonce');
    }
    return nonce;
  }

  // ── 内部方法：根证书管理 ───────────────────────────────────

  /** 重新从磁盘加载信任根证书，供 meta.import_trust_roots 后刷新使用。 */
  reloadTrustedRoots(): number {
    this._rootCerts = this._loadRootCerts(this._rootCaPath);
    this._gatewayCaVerified.clear();
    this._chainVerifiedCache.clear();
    return this._rootCerts.length;
  }

  /** 加载受信根证书列表（空时自动 fallback 重试一次磁盘加载） */
  private _loadTrustedRoots(): crypto.X509Certificate[] {
    if (!this._rootCerts.length) {
      // fallback: 证书可能在构造之后才写入磁盘，重新加载一次
      this._rootCerts = this._loadRootCerts(this._rootCaPath);
      if (!this._rootCerts.length) {
        throw new AuthError('no trusted roots available for auth certificate verification');
      }
    }
    return this._rootCerts;
  }

  /**
   * 加载根证书：内置 + 自定义路径。
   * 在 SDK 的 certs/ 目录下查找 *.crt 文件。
   */
  private _loadRootCerts(rootCaPath: string | null): crypto.X509Certificate[] {
    const candidatePaths: string[] = [];

    if (rootCaPath) {
      candidatePaths.push(rootCaPath);
    }

    // 内置 certs 目录：多种路径策略确保找到
    let normalizedSrcDir: string;
    try {
      normalizedSrcDir = path.dirname(fileURLToPath(import.meta.url));
    } catch {
      normalizedSrcDir = __dirname ?? process.cwd();
    }

    const bundledDirs = [
      path.join(normalizedSrcDir, 'certs'),
      path.join(normalizedSrcDir, '..', 'certs'),
      path.join(normalizedSrcDir, '..', 'src', 'certs'),
      // 从 process.cwd() 出发（vitest 运行时 cwd 通常是包根目录）
      path.join(process.cwd(), 'src', 'certs'),
    ];

    for (const dir of bundledDirs) {
      try {
        if (fs.existsSync(dir)) {
          const files = fs.readdirSync(dir)
            .filter((f) => f.endsWith('.crt'))
            .sort()
            .map((f) => path.join(dir, f));
          candidatePaths.push(...files);
        }
      } catch {
        // 目录不存在或不可访问
      }
    }

    const certs: crypto.X509Certificate[] = [];
    const seenDer = new Set<string>();

    for (const certPath of candidatePaths) {
      let text: string;
      try {
        text = fs.readFileSync(certPath, 'utf-8');
      } catch (e) {
        throw new AuthError(`failed to read root certificate bundle: ${certPath}`);
      }
      const pems = _splitPemBundle(text);
      for (const pem of pems) {
        try {
          const cert = _loadX509(pem);
          const der = _certDer(cert).toString('hex');
          if (seenDer.has(der)) continue;
          seenDer.add(der);
          certs.push(cert);
        } catch {
          // 跳过无法解析的证书
        }
      }
    }

    return certs;
  }

  /** 清理过期的 gateway 缓存条目（供外部定时调用） */
  cleanExpiredCaches(): void {
    const now = Date.now();
    for (const [k, v] of this._gatewayCrlCache) {
      if (v.nextRefreshAt <= now) this._gatewayCrlCache.delete(k);
    }
    for (const [k, v] of this._gatewayOcspCache) {
      for (const [serial, entry] of v) {
        if (entry.nextRefreshAt <= now) v.delete(serial);
      }
      if (v.size === 0) this._gatewayOcspCache.delete(k);
    }
    for (const [k, v] of this._chainVerifiedCache) {
      if (now - v >= 300_000) this._chainVerifiedCache.delete(k);
    }
  }
}
interface ExportedJwk extends JsonObject {
  crv?: string;
}

interface AuthContext extends JsonObject {
  token?: string;
  identity?: IdentityRecord;
  hello?: JsonObject;
}

