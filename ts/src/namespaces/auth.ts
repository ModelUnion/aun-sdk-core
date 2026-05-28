/**
 * Auth 命名空间
 *
 * 提供 auth.registerAid / auth.authenticate 等高层方法，
 * 内部通过 AUNClient 的 transport、auth、discovery 完成实际流程。
 *
 * 与 Python SDK 的 AuthNamespace 完全对齐。
 */

import { AUNError, NotFoundError, StateError, ValidationError } from '../errors.js';
import type { AUNConfig } from '../config.js';
import type { AUNClient } from '../client.js';
import type { ModuleLogger } from '../logger.js';
import type { KeyStore } from '../keystore/index.js';
import { isJsonObject, type IdentityRecord, type JsonObject, type JsonValue, type RpcParams, type RpcResult } from '../types.js';
import { certificateSha256Fingerprint } from '../crypto.js';
import { createSign, createVerify, X509Certificate } from 'node:crypto';

const AGENT_MD_HTTP_TIMEOUT_MS = 30_000;
const AGENT_MD_SIGNATURE_MARKER = '<!-- AUN-SIGNATURE';
const AGENT_MD_SIGNATURE_RE = /^<!-- AUN-SIGNATURE\r?\n(?<body>[\s\S]*?)\r?\n-->\s*$/;
const AGENT_MD_FINGERPRINT_RE = /^sha256:[0-9a-f]{64}$/;

interface AuthNamespaceResult extends IdentityRecord {
  gateway?: string;
  cert_pem?: string;
}

interface AgentMdVerifyResult extends JsonObject {
  status?: 'verified' | 'invalid' | 'unsigned';
  verified?: boolean;
  payload?: string;
  reason?: string;
  aid?: string;
  cert_fingerprint?: string;
  timestamp?: number;
}

interface AuthFlowBridge {
  registerAid: (url: string, aid: string) => Promise<IdentityRecord>;
  authenticate: (url: string, opts?: { aid?: string }) => Promise<AuthNamespaceResult>;
  loadIdentity: (aid?: string) => IdentityRecord;
  loadIdentityOrNone: (aid?: string) => IdentityRecord | null;
  getAccessTokenExpiry?: (identity: IdentityRecord) => number | null;
  refreshCachedTokens?: (gatewayUrl: string, identity: IdentityRecord) => Promise<IdentityRecord>;
}

interface ClientBridge {
  _aid: string | null;
  _gatewayUrl: string | null;
  _identity: IdentityRecord | null;
  _configModel: AUNConfig;
  _keystore: KeyStore;
  _fetchPeerCert?: (aid: string, certFingerprint?: string) => Promise<string>;
  _discovery: {
    discover: (url: string) => Promise<string>;
  };
  _auth: AuthFlowBridge;
  _logger: { for: (module: string) => ModuleLogger };
}

interface AgentMdSignOptions {
  aid?: string;
}

interface AgentMdVerifyOptions {
  aid?: string;
  certPem?: string;
  cert_pem?: string;
}

function agentMdHttpScheme(gatewayUrl: string): string {
  const raw = String(gatewayUrl ?? '').trim().toLowerCase();
  return raw.startsWith('ws://') ? 'http' : 'https';
}

function agentMdAuthority(aid: string, discoveryPort: number | null | undefined): string {
  const host = String(aid ?? '').trim();
  if (!host) return '';
  if (discoveryPort && !host.includes(':')) {
    return `${host}:${discoveryPort}`;
  }
  return host;
}

function parseAgentMdTailSignature(content: string): { payload: string; fields: Record<string, string> | null; parseError?: string } {
  const idx = content.lastIndexOf(AGENT_MD_SIGNATURE_MARKER);
  if (idx < 0) {
    return { payload: content, fields: null };
  }
  if (idx > 0 && content[idx - 1] !== '\n' && content[idx - 1] !== '\r') {
    return { payload: content, fields: null };
  }

  const tail = content.slice(idx);
  const match = tail.match(AGENT_MD_SIGNATURE_RE);
  if (!match) {
    return { payload: content.slice(0, idx), fields: null, parseError: 'malformed signature block' };
  }

  const fields: Record<string, string> = {};
  for (const rawLine of match.groups?.body?.split(/\r?\n/) ?? []) {
    const line = rawLine.trim();
    if (!line) continue;
    const colon = line.indexOf(':');
    if (colon < 0) {
      return { payload: content.slice(0, idx), fields: null, parseError: `malformed signature field: ${line}` };
    }
    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    fields[key] = value;
  }

  for (const required of ['cert_fingerprint', 'timestamp', 'signature']) {
    if (!fields[required]) {
      return { payload: content.slice(0, idx), fields: null, parseError: `signature block missing ${required}` };
    }
  }
  if (!AGENT_MD_FINGERPRINT_RE.test(fields.cert_fingerprint.toLowerCase())) {
    return { payload: content.slice(0, idx), fields: null, parseError: 'invalid cert_fingerprint' };
  }
  if (!Number.isFinite(Number(fields.timestamp))) {
    return { payload: content.slice(0, idx), fields: null, parseError: 'invalid timestamp' };
  }

  return { payload: content.slice(0, idx), fields, parseError: undefined };
}

function extractAgentMDAid(payload: string): string {
  const lines = payload.replace(/^\ufeff/, '').split(/\r?\n/);
  if (!lines.length || lines[0].trim() !== '---') {
    return '';
  }
  for (const line of lines.slice(1)) {
    const trimmed = line.trim();
    if (trimmed === '---') break;
    if (trimmed.startsWith('aid:')) {
      let value = trimmed.slice(4).trim();
      if (value.length >= 2 && value[0] === value[value.length - 1] && (value[0] === '"' || value[0] === '\'')) {
        value = value.slice(1, -1);
      }
      return value.trim();
    }
  }
  return '';
}

function agentMdResult(
  status: 'verified' | 'invalid' | 'unsigned',
  payload: string,
  reason = '',
  aid = '',
  certFingerprint = '',
  timestamp?: number,
): AgentMdVerifyResult {
  const result: AgentMdVerifyResult = {
    status,
    verified: status === 'verified',
    payload,
  };
  if (reason) result.reason = reason;
  if (aid) result.aid = aid;
  if (certFingerprint) result.cert_fingerprint = certFingerprint;
  if (timestamp !== undefined) result.timestamp = timestamp;
  return result;
}

function normalizeIdentityCertPem(identity: IdentityRecord | null): string {
  if (!identity) return '';
  return String(identity.cert ?? identity.cert_pem ?? '').trim();
}

function parseAgentMdTimestamp(value: string): number | undefined {
  const parsed = Number(value.trim());
  return Number.isFinite(parsed) ? Math.trunc(parsed) : undefined;
}

function extractCommonName(subject: string): string {
  const match = subject.match(/(?:^|,\s*)CN=([^,]+)/);
  return match?.[1]?.trim() ?? '';
}

async function fetchWithTimeout(
  input: string,
  init: RequestInit,
  timeoutMs: number = AGENT_MD_HTTP_TIMEOUT_MS,
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

export class AuthNamespace {
  private _client: AUNClient;
  private _log: ModuleLogger;
  private _agentMdCache: Map<string, { text?: string; etag: string; lastModified: string }> = new Map();
  private _agentMdDownloadInflight: Map<string, Promise<string>> = new Map();
  private _agentMdDownloadActive = 0;
  private _agentMdDownloadWaiters: Array<() => void> = [];
  private static readonly AGENT_MD_DOWNLOAD_CONCURRENCY = 8;

  constructor(client: AUNClient) {
    this._client = client;
    this._log = (client as any as ClientBridge)._logger.for('aun_core.namespace.auth');
  }

  private get _internal(): ClientBridge {
    return this._client as any as ClientBridge;
  }

  private async _acquireAgentMdDownloadSlot(): Promise<() => void> {
    if (this._agentMdDownloadActive < AuthNamespace.AGENT_MD_DOWNLOAD_CONCURRENCY) {
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
    if (this._agentMdDownloadActive > 0) {
      this._agentMdDownloadActive -= 1;
    }
  }

  /**
   * 解析 Gateway URL。
   * 优先使用已预置的 _gatewayUrl，否则基于 AID 自动发现。
   *
   * 发现流程：
   * 1. 若 _gatewayUrl 已预置（内存），直接返回
   * 2. 从 keystore metadata 读 cached gateway_url（跨进程复用）
   * 3. 开发环境：先 gateway.{issuer}，再 fallback {aid}（泛域名在开发环境可能不可用）
   * 4. 生产环境：先 {aid}（泛域名 nameservice），再 fallback gateway.{issuer}
   */
  async _resolveGateway(aid?: string): Promise<string> {
    // 访问内部属性
    const client = this._internal;
    const gatewayUrl = client._gatewayUrl;
    if (gatewayUrl) {
      this._log.debug(`_resolveGateway: using preset gateway=${gatewayUrl}`);
      return gatewayUrl;
    }

    const resolvedAid = aid ?? client._aid;
    if (resolvedAid) {
      // 从 keystore metadata 读持久化的 gateway_url（避免每次进程启动都做 well-known discovery）
      try {
        const cachedGateway = this._loadCachedGatewayUrl(resolvedAid);
        if (cachedGateway) {
          this._log.debug(`_resolveGateway from keystore cache aid=${resolvedAid} gateway=${cachedGateway}`);
          client._gatewayUrl = cachedGateway;
          return cachedGateway;
        }
      } catch (exc) {
        this._log.debug(`load cached gateway_url failed: ${exc instanceof Error ? exc.message : String(exc)}`);
      }

      const parts = resolvedAid.split('.');
      const issuerDomain = parts.length > 1 ? parts.slice(1).join('.') : resolvedAid;

      const configModel = client._configModel;
      const port = configModel.discoveryPort;
      const portSuffix = port ? `:${port}` : '';

      const aidUrl = `https://${resolvedAid}${portSuffix}/.well-known/aun-gateway`;
      const gatewayDomainUrl = `https://gateway.${issuerDomain}${portSuffix}/.well-known/aun-gateway`;
      const discovery = client._discovery;

      // 开发环境：先 gateway.{issuer}（固定域名），再 fallback {aid}（泛域名）
      // 生产环境：先 {aid}（泛域名），再 fallback gateway.{issuer}
      const [primaryUrl, fallbackUrl] = configModel.verifySsl
        ? [aidUrl, gatewayDomainUrl]
        : [gatewayDomainUrl, aidUrl];

      this._log.debug(`_resolveGateway start: aid=${resolvedAid} primary=${primaryUrl}`);
      try {
        const url = await discovery.discover(primaryUrl);
        this._log.debug(`_resolveGateway primary ok: aid=${resolvedAid} gateway=${url}`);
        this._persistGatewayUrl(resolvedAid, url);
        return url;
      } catch (exc) {
        // 主路径失败，尝试 fallback
        this._log.warn(`_resolveGateway primary failed, trying fallback: aid=${resolvedAid} primary=${primaryUrl} err=${exc instanceof Error ? exc.message : String(exc)}`);
      }

      const url = await discovery.discover(fallbackUrl);
      this._log.debug(`_resolveGateway fallback ok: aid=${resolvedAid} gateway=${url}`);
      this._persistGatewayUrl(resolvedAid, url);
      return url;
    }

    throw new ValidationError(
      "unable to resolve gateway: set client._gatewayUrl or provide 'aid' for auto-discovery",
    );
  }

  /**
  /**
   * 从 keystore metadata 读取 cached gateway_url（用于跨进程复用，避免重做 discovery）
   *
   * 重要：本方法**绝不**为 aid 创建空壳目录。仅当正式 AID 目录已存在
   * （已注册）时才读取；否则返回空字符串。
   */
  _loadCachedGatewayUrl(aid: string): string {
    if (!aid) return '';
    const keystore = this._internal._keystore as KeyStore & {
      _aidsRoot?: string;
      _getDB?: (aid: string) => { getMetadata: (k: string) => string | null };
    };
    try {
      // 仅当正式目录存在时才读
      if (keystore._aidsRoot) {
        const fs = require('node:fs') as typeof import('node:fs');
        const path = require('node:path') as typeof import('node:path');
        const safe = aid.replace(/[\/\\:]/g, '_');
        if (!fs.existsSync(path.join(keystore._aidsRoot, safe))) return '';
      }
      const db = keystore._getDB?.(aid);
      if (!db || typeof db.getMetadata !== 'function') return '';
      const raw = db.getMetadata('gateway_url');
      if (!raw) return '';
      try {
        const value = JSON.parse(raw);
        if (typeof value === 'string') return value.trim();
      } catch {
        // 解析失败回退到裸字符串
      }
      return String(raw).trim();
    } catch {
      return '';
    }
  }

  /**
   * 持久化 gateway_url 到 keystore metadata，供跨进程复用。
   *
   * 重要：本方法**绝不**为 aid 创建空壳目录。仅当正式 AID 目录已存在
   * （已注册）时才写入；否则跳过——register_aid 完成后会重新写入。
   */
  _persistGatewayUrl(aid: string, gatewayUrl: string): void {
    if (!gatewayUrl || !aid) return;
    const keystore = this._internal._keystore as KeyStore & {
      _aidsRoot?: string;
      _getDB?: (aid: string) => { setMetadata: (k: string, v: string) => void };
    };
    try {
      // 仅当正式目录存在时才写
      if (keystore._aidsRoot) {
        const fs = require('node:fs') as typeof import('node:fs');
        const path = require('node:path') as typeof import('node:path');
        const safe = aid.replace(/[\/\\:]/g, '_');
        if (!fs.existsSync(path.join(keystore._aidsRoot, safe))) {
          this._log.debug(`persist gateway_url skipped (no identity dir): aid=${aid}`);
          return;
        }
      }
      const db = keystore._getDB?.(aid);
      if (!db || typeof db.setMetadata !== 'function') return;
      db.setMetadata('gateway_url', JSON.stringify(gatewayUrl));
    } catch (exc) {
      this._log.debug(`persist gateway_url failed aid=${aid} err=${exc instanceof Error ? exc.message : String(exc)}`);
    }
  }

  /**
   * 注册新 AID（必须显式调用，绝不会被 SDK 内部自动触发）。
   *
   * 与旧 `createAid` 的差异：
   * - 不再混合 load/create 语义；本地已有该 AID → IdentityConflictError
   * - 注册后**不**继续登录/连接；应用层需显式 authenticate / connect
   * - 失败不留磁盘痕迹（临时目录由 AUNClient 启动时清理）
   */
  async registerAid(params: RpcParams): Promise<AuthNamespaceResult> {
    const tStart = Date.now();
    const aid = String(params?.aid ?? '');
    if (!aid) throw new Error("auth.registerAid requires 'aid'");

    const client = this._internal;
    this._log.debug(`registerAid enter: aid=${aid}`);
    const gatewayUrl = await this._resolveGateway(aid);
    client._gatewayUrl = gatewayUrl;

    const auth = client._auth;
    try {
      const result = await auth.registerAid(gatewayUrl, aid);
      client._aid = aid;
      client._identity = auth.loadIdentityOrNone(aid);
      this._persistGatewayUrl(aid, gatewayUrl);
      this._log.info(`registerAid success: aid=${aid} gateway=${gatewayUrl}`);
      this._log.debug(`registerAid exit: elapsed=${Date.now() - tStart}ms aid=${aid}`);
      return {
        aid: result.aid,
        cert_pem: result.cert,
        gateway: gatewayUrl,
      };
    } catch (err) {
      this._log.error(`registerAid failed: aid=${aid} err=${err instanceof Error ? err.message : String(err)}`, err instanceof Error ? err : undefined);
      this._log.debug(`registerAid exit (error): elapsed=${Date.now() - tStart}ms aid=${aid} err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }


  /** 加载本地已注册身份。本地无完整身份 → 抛 StateError。 */
  loadIdentity(params?: RpcParams): IdentityRecord {
    const aid = String((params ?? {})?.aid ?? '').trim() || undefined;
    return this._internal._auth.loadIdentity(aid);
  }

  /** 加载本地已注册身份，不存在时返回 null。 */
  loadIdentityOrNull(params?: RpcParams): IdentityRecord | null {
    const aid = String((params ?? {})?.aid ?? '').trim() || undefined;
    return this._internal._auth.loadIdentityOrNone(aid);
  }

  /**
   * 获取对端 AID 的证书 PEM（不要求本机有任何身份）。
   * - 优先走本地 public/certs/ 缓存（不碰 private/）
   * - 缓存未命中 → PKI HTTP 端点 + 链验证 + 落本地缓存
   */
  async fetchPeerCert(params: RpcParams): Promise<string> {
    const aid = String(params?.aid ?? '').trim();
    if (!aid) throw new Error("auth.fetchPeerCert requires 'aid'");
    const fp = String((params as { cert_fingerprint?: unknown })?.cert_fingerprint ?? '').trim() || undefined;
    if (typeof this._internal._fetchPeerCert !== 'function') {
      throw new Error('client does not support _fetchPeerCert');
    }
    return String(await this._internal._fetchPeerCert(aid, fp)).trim();
  }

  /** 认证（登录） */
  async authenticate(params?: RpcParams): Promise<AuthNamespaceResult> {
    const tStart = Date.now();
    const request = { ...(params ?? {}) };
    const aid = request.aid as string | undefined;

    const client = this._internal;
    this._log.debug(`authenticate enter: aid=${aid ?? '-'}`);
    const gatewayUrl = await this._resolveGateway(aid);
    client._gatewayUrl = gatewayUrl;

    const auth = client._auth;
    try {
      const result = await auth.authenticate(gatewayUrl, { aid });
      client._aid = result.aid ?? null;
      client._identity = auth.loadIdentityOrNone(String(result.aid));
      this._persistGatewayUrl(String(result.aid ?? aid ?? ''), gatewayUrl);
      this._log.info(`authenticate success: aid=${result.aid} gateway=${gatewayUrl}`);
      this._log.debug(`authenticate exit: elapsed=${Date.now() - tStart}ms aid=${aid ?? '-'}`);
      return result;
    } catch (err) {
      this._log.error(`authenticate failed: aid=${aid ?? '-'} err=${err instanceof Error ? err.message : String(err)}`, err instanceof Error ? err : undefined);
      this._log.debug(`authenticate exit (error): elapsed=${Date.now() - tStart}ms aid=${aid ?? '-'} err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  async signAgentMd(content: string, opts?: AgentMdSignOptions): Promise<string> {
    const tStart = Date.now();
    const client = this._internal;
    const targetAid = String(opts?.aid ?? client._aid ?? '').trim();
    this._log.debug(`signAgentMd enter: aid=${targetAid || '-'} content_len=${content?.length ?? 0}`);
    try {
    const identity = client._auth.loadIdentityOrNone(targetAid || undefined);
    if (!identity) {
      this._log.error(`signAgentMd failed: no local identity for aid=${targetAid || '-'}`);
      throw new StateError('no local identity found, call auth.registerAid() first');
    }

    const privateKeyPem = String(identity.private_key_pem ?? '').trim();
    const certPem = normalizeIdentityCertPem(identity);
    if (!privateKeyPem || !certPem) {
      this._log.error(`signAgentMd failed: identity missing key/cert aid=${identity.aid ?? '-'}`);
      throw new StateError('local identity missing private key or certificate');
    }

    let payload = parseAgentMdTailSignature(String(content ?? '')).payload;
    if (payload && !payload.endsWith('\n') && !payload.endsWith('\r')) {
      payload += '\n';
    }

    const signer = createSign('sha256');
    signer.update(payload);
    signer.end();
    const signature = signer.sign(privateKeyPem).toString('base64');
    const fingerprint = certificateSha256Fingerprint(certPem);
    if (!fingerprint) {
      this._log.error(`signAgentMd failed: cert fingerprint computation failed aid=${identity.aid ?? '-'}`);
      throw new StateError('agent.md cert fingerprint failed');
    }

    const signedBlock = [
      AGENT_MD_SIGNATURE_MARKER,
      `cert_fingerprint: ${fingerprint}`,
      `timestamp: ${Math.floor(Date.now() / 1000)}`,
      `signature: ${signature}`,
      '-->',
    ].join('\n');

    this._log.debug(`signAgentMd exit: elapsed=${Date.now() - tStart}ms aid=${identity.aid ?? '-'} fingerprint=${fingerprint.slice(0, 23)}...`);
    return payload + signedBlock;
    } catch (err) {
      this._log.debug(`signAgentMd exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  async verifyAgentMd(content: string, opts?: AgentMdVerifyOptions): Promise<AgentMdVerifyResult> {
    const tStart = Date.now();
    this._log.debug(`verifyAgentMd enter: aid_hint=${opts?.aid ?? '-'} content_len=${content?.length ?? 0}`);
    try {
    const { payload, fields, parseError } = parseAgentMdTailSignature(String(content ?? ''));
    if (!fields) {
      if (!parseError) {
        this._log.debug(`verifyAgentMd exit: elapsed=${Date.now() - tStart}ms (unsigned)`);
        return agentMdResult('unsigned', payload);
      }
      this._log.warn(`verifyAgentMd invalid: parse_error=${parseError}`);
      this._log.debug(`verifyAgentMd exit: elapsed=${Date.now() - tStart}ms (parse_error)`);
      return agentMdResult('invalid', payload, parseError);
    }

    let expectedAid = String(opts?.aid ?? '').trim();
    const payloadAid = extractAgentMDAid(payload);
    if (expectedAid && payloadAid && expectedAid !== payloadAid) {
      this._log.warn(`verifyAgentMd invalid: aid_mismatch hint=${expectedAid} payload_aid=${payloadAid}`);
      this._log.debug(`verifyAgentMd exit: elapsed=${Date.now() - tStart}ms (aid_mismatch)`);
      return agentMdResult('invalid', payload, 'aid mismatch', payloadAid);
    }
    if (!expectedAid) {
      expectedAid = payloadAid;
    }

    let certPem = String(opts?.certPem ?? opts?.cert_pem ?? '').trim();
    if (!certPem) {
      if (!expectedAid) {
        this._log.warn('verifyAgentMd invalid: aid required to verify agent.md');
        this._log.debug(`verifyAgentMd exit: elapsed=${Date.now() - tStart}ms (aid_required)`);
        return agentMdResult('invalid', payload, 'aid required to verify agent.md');
      }
      // 通过 _internal 直接调用，保留 this 绑定（解构后调用会丢失 this，导致 _clientLog 等成员访问失败）
      if (typeof this._internal._fetchPeerCert !== 'function') {
        this._log.warn(`verifyAgentMd invalid: client cannot fetch peer cert aid=${expectedAid}`);
        this._log.debug(`verifyAgentMd exit: elapsed=${Date.now() - tStart}ms (no_fetch_fn)`);
        return agentMdResult('invalid', payload, 'aid required to verify agent.md', expectedAid);
      }
      try {
        certPem = String(await this._internal._fetchPeerCert(expectedAid, fields.cert_fingerprint)).trim();
      } catch (error) {
        this._log.warn(`verifyAgentMd invalid: peer cert fetch failed aid=${expectedAid} err=${String(error)}`);
        this._log.debug(`verifyAgentMd exit: elapsed=${Date.now() - tStart}ms (cert_fetch_failed)`);
        return agentMdResult('invalid', payload, String(error), expectedAid, fields.cert_fingerprint);
      }
    }

    let cert: X509Certificate;
    try {
      cert = new X509Certificate(certPem);
    } catch (error) {
      this._log.warn(`verifyAgentMd invalid: cert parse failed aid=${expectedAid || '-'} err=${String(error)}`);
      this._log.debug(`verifyAgentMd exit: elapsed=${Date.now() - tStart}ms (cert_parse_failed)`);
      return agentMdResult('invalid', payload, `invalid certificate: ${String(error)}`, expectedAid, fields.cert_fingerprint);
    }

    const actualFingerprint = certificateSha256Fingerprint(certPem);
    if (!actualFingerprint || actualFingerprint.toLowerCase() !== fields.cert_fingerprint.toLowerCase()) {
      this._log.warn(`verifyAgentMd invalid: fingerprint_mismatch expected=${fields.cert_fingerprint} actual=${actualFingerprint}`);
      this._log.debug(`verifyAgentMd exit: elapsed=${Date.now() - tStart}ms (fingerprint_mismatch)`);
      return agentMdResult('invalid', payload, 'certificate fingerprint mismatch', expectedAid, fields.cert_fingerprint);
    }

    const cn = extractCommonName(cert.subject);
    if (expectedAid && cn && cn !== expectedAid) {
      this._log.warn(`verifyAgentMd invalid: cert cn=${cn} aid=${expectedAid}`);
      this._log.debug(`verifyAgentMd exit: elapsed=${Date.now() - tStart}ms (cn_mismatch)`);
      return agentMdResult('invalid', payload, 'certificate aid mismatch', expectedAid, fields.cert_fingerprint);
    }

    const signature = Buffer.from(fields.signature, 'base64');
    if (!signature.length) {
      this._log.warn(`verifyAgentMd invalid: empty signature aid=${expectedAid || '-'}`);
      this._log.debug(`verifyAgentMd exit: elapsed=${Date.now() - tStart}ms (empty_signature)`);
      return agentMdResult('invalid', payload, 'invalid signature', expectedAid, fields.cert_fingerprint);
    }

    const verifier = createVerify('sha256');
    verifier.update(payload);
    verifier.end();
    const ok = verifier.verify(cert.publicKey, signature);
    if (!ok) {
      this._log.warn(`verifyAgentMd invalid: signature verification failed aid=${expectedAid || '-'}`);
      this._log.debug(`verifyAgentMd exit: elapsed=${Date.now() - tStart}ms (signature_failed)`);
      return agentMdResult('invalid', payload, 'signature verification failed', expectedAid, fields.cert_fingerprint, parseAgentMdTimestamp(fields.timestamp));
    }

    this._log.debug(`verifyAgentMd exit: elapsed=${Date.now() - tStart}ms (verified) aid=${expectedAid || payloadAid}`);
    return agentMdResult('verified', payload, '', expectedAid || payloadAid, fields.cert_fingerprint, parseAgentMdTimestamp(fields.timestamp));
    } catch (err) {
      this._log.debug(`verifyAgentMd exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  private async _resolveAgentMdUrl(aid: string): Promise<string> {
    const resolvedAid = String(aid ?? '').trim();
    if (!resolvedAid) {
      throw new ValidationError('agent.md requires non-empty aid');
    }
    const client = this._internal;
    let gatewayUrl = client._gatewayUrl ?? '';
    if (!gatewayUrl) {
      try {
        gatewayUrl = await this._resolveGateway(resolvedAid);
      } catch {
        gatewayUrl = '';
      }
    }
    const configModel = client._configModel;
    const discoveryPort = configModel.discoveryPort;
    const authority = agentMdAuthority(resolvedAid, discoveryPort);
    return `${agentMdHttpScheme(gatewayUrl)}://${authority}/agent.md`;
  }

  private async _ensureAgentMdUploadToken(aid: string, gatewayUrl: string): Promise<string> {
    const auth = this._internal._auth;

    let identity = auth.loadIdentityOrNone(aid);
    if (!identity) {
      throw new StateError('no local identity found, call auth.registerAid() first');
    }

    const cachedToken = String(identity.access_token ?? '');
    const expiresAt = auth.getAccessTokenExpiry ? auth.getAccessTokenExpiry(identity) : null;
    if (cachedToken && (expiresAt === null || expiresAt > Date.now() / 1000 + 30)) {
      return cachedToken;
    }

    if (typeof auth.refreshCachedTokens === 'function' && identity.refresh_token) {
      try {
        identity = await auth.refreshCachedTokens(gatewayUrl, identity);
        const refreshedToken = String(identity.access_token ?? '');
        const refreshedExpiry = auth.getAccessTokenExpiry ? auth.getAccessTokenExpiry(identity) : null;
        if (refreshedToken && (refreshedExpiry === null || refreshedExpiry > Date.now() / 1000 + 30)) {
          return refreshedToken;
        }
      } catch {
        // refresh 失败时回退到完整 authenticate
      }
    }

    const result = await this.authenticate({ aid });
    const token = String(result.access_token ?? '');
    if (!token) {
      throw new StateError('authenticate did not return access_token');
    }
    return token;
  }

  async uploadAgentMd(content: string): Promise<JsonObject> {
    const tStart = Date.now();
    this._log.debug(`uploadAgentMd enter: content_len=${content?.length ?? 0}`);
    try {
    const client = this._internal;
    const auth = client._auth;
    const identity = auth.loadIdentityOrNone(client._aid ?? undefined);
    if (!identity) {
      throw new StateError('no local identity found, call auth.registerAid() first');
    }
    const aid = String(identity.aid ?? client._aid ?? '').trim();
    if (!aid) {
      throw new StateError('no local identity found, call auth.registerAid() first');
    }

    const gatewayUrl = await this._resolveGateway(aid);
    client._gatewayUrl = gatewayUrl;
    const token = await this._ensureAgentMdUploadToken(aid, gatewayUrl);
    const response = await fetchWithTimeout(await this._resolveAgentMdUrl(aid), {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'text/markdown; charset=utf-8',
      },
      body: content,
    });

    if (response.status === 404) {
      throw new NotFoundError(`agent.md endpoint not found for aid: ${aid}`);
    }
    if (!response.ok) {
      const message = (await response.text()).trim();
      throw new AUNError(
        `upload agent.md failed: HTTP ${response.status}${message ? ` - ${message}` : ''}`,
      );
    }
    const payload = await response.json() as JsonValue;
    if (!isJsonObject(payload)) {
      throw new AUNError('upload agent.md returned invalid JSON payload');
    }
    this._log.debug(`uploadAgentMd exit: elapsed=${Date.now() - tStart}ms aid=${aid}`);
    return payload;
    } catch (err) {
      this._log.debug(`uploadAgentMd exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }


  async headAgentMd(aid: string): Promise<JsonObject> {
    const tStart = Date.now();
    const targetAid = String(aid ?? '').trim();
    if (!targetAid) {
      throw new ValidationError('headAgentMd requires non-empty aid');
    }
    this._log.debug(`headAgentMd enter: aid=${targetAid}`);
    try {
      const response = await fetchWithTimeout(await this._resolveAgentMdUrl(targetAid), {
        method: 'HEAD',
        headers: { Accept: 'text/markdown' },
        redirect: 'follow',
      }, 15_000);
      const respHeaders = response.headers;
      const etag = respHeaders ? String(respHeaders.get('ETag') ?? '').trim() : '';
      const lastModified = respHeaders ? String(respHeaders.get('Last-Modified') ?? '').trim() : '';
      const cached = this._agentMdCache.get(targetAid);
      if (response.status === 404) {
        this._log.debug(`headAgentMd exit (not_found): elapsed=${Date.now() - tStart}ms aid=${targetAid}`);
        return { aid: targetAid, found: false, etag: '', last_modified: '', status: 404 };
      }
      const resultEtag = response.status === 304 ? (etag || cached?.etag || '') : etag;
      const resultLastModified = response.status === 304 ? (lastModified || cached?.lastModified || '') : lastModified;
      if (response.status < 200 || (response.status >= 300 && response.status !== 304)) {
        throw new AUNError(`head agent.md failed: HTTP ${response.status}`);
      }
      if (resultEtag || resultLastModified) {
        this._agentMdCache.set(targetAid, {
          ...(typeof cached?.text === 'string' ? { text: cached.text } : {}),
          etag: resultEtag,
          lastModified: resultLastModified,
        });
      }
      this._log.debug(`headAgentMd exit: elapsed=${Date.now() - tStart}ms aid=${targetAid} status=${response.status} etag=${resultEtag || '-'}`);
      return { aid: targetAid, found: true, etag: resultEtag, last_modified: resultLastModified, status: response.status };
    } catch (err) {
      this._log.debug(`headAgentMd exit (error): elapsed=${Date.now() - tStart}ms aid=${targetAid} err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  async downloadAgentMd(aid: string): Promise<string> {
    const targetAid = String(aid ?? '').trim();
    if (!targetAid) {
      throw new ValidationError('downloadAgentMd requires non-empty aid');
    }
    const existing = this._agentMdDownloadInflight.get(targetAid);
    if (existing) {
      return await existing;
    }

    const task = (async () => {
      const tStart = Date.now();
      this._log.debug(`downloadAgentMd enter: aid=${targetAid}`);
      const release = await this._acquireAgentMdDownloadSlot();
      try {
        const text = await this._downloadAgentMdOnce(targetAid, tStart);
        this._log.debug(`downloadAgentMd exit: elapsed=${Date.now() - tStart}ms aid=${targetAid} bytes=${text.length}`);
        return text;
      } catch (err) {
        this._log.debug(`downloadAgentMd exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
        throw err;
      } finally {
        release();
      }
    })();
    this._agentMdDownloadInflight.set(targetAid, task);
    task.finally(() => {
      if (this._agentMdDownloadInflight.get(targetAid) === task) {
        this._agentMdDownloadInflight.delete(targetAid);
      }
    }).catch(() => undefined);
    return await task;
  }

  private async _downloadAgentMdOnce(targetAid: string, tStart: number): Promise<string> {
    const cached = this._agentMdCache.get(targetAid);
    const hasCachedText = typeof cached?.text === 'string';
    const requestHeaders: Record<string, string> = { Accept: 'text/markdown' };

    const agentMdUrl = await this._resolveAgentMdUrl(targetAid);
    let response = await fetchWithTimeout(agentMdUrl, {
      method: 'GET',
      headers: requestHeaders,
      redirect: 'follow',
    });

    if (response.status === 304 && hasCachedText) {
      this._log.debug(`downloadAgentMd exit (not_modified): elapsed=${Date.now() - tStart}ms aid=${targetAid}`);
      return cached.text as string;
    }
    if (response.status === 304) {
      this._log.debug(`downloadAgentMd retry unconditional GET after 304 without cached body: aid=${targetAid}`);
      response = await fetchWithTimeout(agentMdUrl, {
        method: 'GET',
        headers: { Accept: 'text/markdown' },
        cache: 'reload',
        redirect: 'follow',
      });
    }
    if (response.status === 404) {
      throw new NotFoundError(`agent.md not found for aid: ${targetAid}`);
    }
    if (!response.ok) {
      const message = (await response.text()).trim();
      throw new AUNError(
        `download agent.md failed: HTTP ${response.status}${message ? ` - ${message}` : ''}`,
      );
    }
    const text = await response.text();
    const respHeaders = response.headers;
    const etag = respHeaders ? String(respHeaders.get('ETag') ?? '').trim() : '';
    const lastModified = respHeaders ? String(respHeaders.get('Last-Modified') ?? '').trim() : '';
    if (etag || lastModified) {
      this._agentMdCache.set(targetAid, { text, etag, lastModified });
    }
    return text;
  }

  /** 下载证书 */
  async downloadCert(params?: RpcParams): Promise<RpcResult> {
    const tStart = Date.now();
    this._log.debug(`downloadCert enter`);
    try {
      const result = await this._client.call('auth.download_cert', params ?? {});
      this._log.debug(`downloadCert exit: elapsed=${Date.now() - tStart}ms`);
      return result;
    } catch (err) {
      this._log.debug(`downloadCert exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 请求签发证书 */
  async requestCert(params: RpcParams): Promise<RpcResult> {
    const tStart = Date.now();
    this._log.debug(`requestCert enter`);
    try {
      const result = await this._client.call('auth.request_cert', params);
      this._log.debug(`requestCert exit: elapsed=${Date.now() - tStart}ms`);
      return result;
    } catch (err) {
      this._log.debug(`requestCert exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 续期证书 */
  async renewCert(params?: RpcParams): Promise<RpcResult> {
    const tStart = Date.now();
    this._log.debug(`renewCert enter`);
    try {
      const result = await this._client.call('auth.renew_cert', params ?? {});
      this._log.debug(`renewCert exit: elapsed=${Date.now() - tStart}ms`);
      return result;
    } catch (err) {
      this._log.debug(`renewCert exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 密钥轮换 */
  async rekey(params?: RpcParams): Promise<RpcResult> {
    const tStart = Date.now();
    this._log.debug(`rekey enter`);
    try {
      const result = await this._client.call('auth.rekey', params ?? {});
      this._log.debug(`rekey exit: elapsed=${Date.now() - tStart}ms`);
      return result;
    } catch (err) {
      this._log.debug(`rekey exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 获取信任根证书列表 */
  async trustRoots(params?: RpcParams): Promise<RpcResult> {
    const tStart = Date.now();
    this._log.debug(`trustRoots enter`);
    try {
      const result = await this._client.call('meta.trust_roots', params ?? {});
      this._log.debug(`trustRoots exit: elapsed=${Date.now() - tStart}ms`);
      return result;
    } catch (err) {
      this._log.debug(`trustRoots exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /**
   * 检查指定 AID 的本地和远程状态。
   * 与 Python SDK namespaces/auth_namespace.py:check_aid 对应。
   */
  async checkAid(params: RpcParams): Promise<JsonObject> {
    const tStart = Date.now();
    const aid = String(params?.aid ?? '').trim();
    if (!aid) throw new ValidationError("auth.check_aid requires 'aid'");
    this._log.debug(`checkAid enter: aid=${aid}`);
    try {
      const result = this._checkLocalAid(aid);
      const local = result.local as JsonObject;
      if (!local?.complete) {
        const remote = await this._checkRemoteAidRegistration(aid);
        result.remote = remote;
        const remoteStatus = (remote as JsonObject)?.status;
        if (remoteStatus === 'available') {
          result.status = 'available';
          result.can_register = true;
        } else if (remoteStatus === 'registered') {
          result.status = 'registered_remote';
          result.can_register = false;
        } else {
          result.status = 'unknown';
          result.can_register = false;
        }
      }
      this._log.debug(`checkAid exit: elapsed=${Date.now() - tStart}ms aid=${aid} status=${result.status}`);
      return result;
    } catch (err) {
      this._log.debug(`checkAid exit (error): elapsed=${Date.now() - tStart}ms aid=${aid} err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  private _checkLocalAid(aid: string): JsonObject {
    const client = this._internal;
    const keystore = client._keystore;
    const identity = client._auth.loadIdentityOrNone(aid);

    let keyPair: { private_key_pem?: string; public_key_der_b64?: string } | null = null;
    let keyError = '';
    try {
      keyPair = keystore.loadKeyPair(aid) as any;
    } catch (e) {
      keyError = e instanceof Error ? e.message : String(e);
    }

    let certPem: string | null = null;
    let certError = '';
    try {
      certPem = keystore.loadCert(aid);
    } catch (e) {
      certError = e instanceof Error ? e.message : String(e);
    }

    const privateKeyPresent = !!(keyPair && keyPair.private_key_pem);
    const publicKeyPresent = !!(keyPair && keyPair.public_key_der_b64);
    const certPresent = !!certPem;
    const certInfo = certPresent ? this._inspectCert(aid, certPem!) : { present: false, valid: false, expired: false };
    const certValid = !!(certInfo as any).valid;
    const localComplete = privateKeyPresent && publicKeyPresent && certPresent && certValid;

    const issues: string[] = [];
    if (!identity) issues.push('local identity not found');
    if (!privateKeyPresent) issues.push('private key missing');
    if (!publicKeyPresent) issues.push('public key missing');
    if (!certPresent) {
      issues.push('certificate missing');
    } else if ((certInfo as any).parse_error) {
      issues.push(`certificate invalid: ${(certInfo as any).parse_error}`);
    } else if ((certInfo as any).expired) {
      issues.push('certificate expired');
    } else if (!certValid) {
      issues.push('certificate not currently valid');
    }
    if (keyError) issues.push(`key load error: ${keyError}`);
    if (certError) issues.push(`certificate load error: ${certError}`);

    return {
      aid,
      status: localComplete ? 'local_ready' : 'local_incomplete',
      can_register: localComplete ? false : null,
      local: {
        exists: identity !== null,
        complete: localComplete,
        private_key: privateKeyPresent,
        public_key: publicKeyPresent,
        certificate: certInfo,
        issues,
      },
      remote: {
        status: localComplete ? 'not_checked' : 'pending',
      },
    };
  }

  private _inspectCert(aid: string, certPem: string): JsonObject {
    const result: JsonObject = { present: true, valid: false, expired: false };
    try {
      const cert = new X509Certificate(certPem);
      const now = Date.now();
      const notBefore = new Date(cert.validFrom).getTime();
      const notAfter = new Date(cert.validTo).getTime();
      const valid = now >= notBefore && now <= notAfter;
      const expired = now > notAfter;
      const fingerprint = certificateSha256Fingerprint(certPem);
      const cn = extractCommonName(cert.subject);
      const aidMatches = !cn || cn === aid;

      result.valid = valid && aidMatches;
      result.expired = expired;
      result.not_before = new Date(cert.validFrom).toISOString();
      result.not_after = new Date(cert.validTo).toISOString();
      result.expires_at = Math.floor(notAfter / 1000);
      result.seconds_until_expiry = Math.floor((notAfter - now) / 1000);
      result.fingerprint = fingerprint;
      result.subject_cn = cn;
      result.aid_matches = aidMatches;

      if (cn && cn !== aid) {
        result.valid = false;
        result.parse_error = `certificate CN mismatch: ${cn}`;
      }
    } catch (e) {
      result.parse_error = e instanceof Error ? e.message : String(e);
    }
    return result;
  }

  private async _checkRemoteAidRegistration(aid: string): Promise<JsonObject> {
    try {
      const content = await this.downloadAgentMd(aid);
      return {
        status: 'registered',
        registered: true,
        available: false,
        source: 'agent.md',
        agent_md_bytes: new TextEncoder().encode(content).length,
        agent_md_aid: extractAgentMDAid(content),
      };
    } catch (err) {
      if (err instanceof NotFoundError) {
        return {
          status: 'available',
          registered: false,
          available: true,
          source: 'agent.md',
        };
      }
      return {
        status: 'unknown',
        registered: null,
        available: null,
        source: 'agent.md',
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }
}
