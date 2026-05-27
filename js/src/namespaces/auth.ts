// ── AuthNamespace（认证命名空间 — 完整实现）──────────────────

import type { AUNClient } from '../client.js';
import { AUNError, NotFoundError, StateError, ValidationError } from '../errors.js';
import type { ModuleLogger } from '../logger.js';
import { isJsonObject, type IdentityRecord, type JsonObject, type JsonValue, type RpcParams, type RpcResult } from '../types.js';
import {
  base64ToUint8,
  pemToArrayBuffer,
  uint8ToBase64,
  certificateSha256Fingerprint,
  ecdsaSignDer,
  ecdsaVerifyDer,
  importCertPublicKeyEcdsa,
  importPrivateKeyEcdsa,
} from '../crypto.js';

const _noopLog: ModuleLogger = { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} };

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
  authenticate: (url: string, aid?: string) => Promise<AuthNamespaceResult>;
  loadIdentityOrNone: (aid?: string) => Promise<IdentityRecord | null>;
  getAccessTokenExpiry: (identity: IdentityRecord) => number | null;
  refreshCachedTokens?: (gatewayUrl: string, identity: IdentityRecord) => Promise<IdentityRecord>;
}

interface ClientBridge {
  _aid: string | null;
  _identity: IdentityRecord | null;
  _fetchPeerCert?: (aid: string, certFingerprint?: string) => Promise<string>;
  _auth: AuthFlowBridge;
  _keystore?: {
    getMetadata?: (aid: string, key: string) => Promise<string>;
    setMetadata?: (aid: string, key: string, value: string) => Promise<void>;
    loadKeyPair?: (aid: string) => Promise<{ private_key_pem?: string; public_key_der_b64?: string } | null>;
    loadCert?: (aid: string) => Promise<string | null>;
  };
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

function readDerLength(bytes: Uint8Array, offset: number): { length: number; lengthBytes: number } | null {
  const first = bytes[offset];
  if (first === undefined) return null;
  if (first < 0x80) {
    return { length: first, lengthBytes: 1 };
  }
  const count = first & 0x7f;
  if (count === 0 || count > 4 || offset + count >= bytes.length) {
    return null;
  }
  let length = 0;
  for (let i = 0; i < count; i++) {
    length = (length << 8) | bytes[offset + 1 + i];
  }
  return { length, lengthBytes: 1 + count };
}

function extractCommonNameFromCertPem(certPem: string): string {
  try {
    const bytes = new Uint8Array(pemToArrayBuffer(certPem));
    const oid = [0x06, 0x03, 0x55, 0x04, 0x03];
    const decoder = new TextDecoder();
    let commonName = '';
    for (let i = 0; i <= bytes.length - oid.length - 2; i++) {
      let matched = true;
      for (let j = 0; j < oid.length; j++) {
        if (bytes[i + j] !== oid[j]) {
          matched = false;
          break;
        }
      }
      if (!matched) continue;

      const tag = bytes[i + oid.length];
      const lengthInfo = readDerLength(bytes, i + oid.length + 1);
      if (!lengthInfo) continue;
      const start = i + oid.length + 1 + lengthInfo.lengthBytes;
      const end = start + lengthInfo.length;
      if (end > bytes.length) continue;
      const valueBytes = bytes.slice(start, end);
      if (tag === 0x0c || tag === 0x13 || tag === 0x16 || tag === 0x14 || tag === 0x1e) {
        commonName = decoder.decode(valueBytes).trim();
      } else {
        commonName = decoder.decode(valueBytes).trim();
      }
    }
    return commonName;
  } catch {
    return '';
  }
}

/** 从 PEM 证书 DER 中解析 validity（notBefore / notAfter）时间戳 */
function parseCertValidity(certPem: string): { notBefore: number; notAfter: number } | null {
  try {
    const der = new Uint8Array(pemToArrayBuffer(certPem));
    // ASN.1 X.509 结构：SEQUENCE { tbsCertificate SEQUENCE { version, serial, sigAlg, issuer, validity, ... } }
    // validity 是 tbsCertificate 中第 5 个字段（0-indexed: 4）
    // 简化方法：搜索连续两个 UTCTime 或 GeneralizedTime 标签
    const dates: number[] = [];
    for (let i = 0; i < der.length - 2 && dates.length < 2; i++) {
      const tag = der[i];
      if (tag !== 0x17 && tag !== 0x18) continue; // UTCTime=0x17, GeneralizedTime=0x18
      const len = der[i + 1];
      if (len === 0 || len > 20 || i + 2 + len > der.length) continue;
      const str = new TextDecoder().decode(der.slice(i + 2, i + 2 + len));
      const ts = parseAsn1Time(tag, str);
      if (ts !== null) {
        dates.push(ts);
        i += 1 + len; // 跳过已解析的时间
      }
    }
    if (dates.length >= 2) {
      return { notBefore: dates[0], notAfter: dates[1] };
    }
    return null;
  } catch {
    return null;
  }
}

function parseAsn1Time(tag: number, str: string): number | null {
  try {
    if (tag === 0x17) {
      // UTCTime: YYMMDDHHMMSSZ
      const cleaned = str.replace(/Z$/i, '');
      if (cleaned.length < 12) return null;
      let year = parseInt(cleaned.slice(0, 2), 10);
      year += year >= 50 ? 1900 : 2000;
      const month = parseInt(cleaned.slice(2, 4), 10) - 1;
      const day = parseInt(cleaned.slice(4, 6), 10);
      const hour = parseInt(cleaned.slice(6, 8), 10);
      const min = parseInt(cleaned.slice(8, 10), 10);
      const sec = parseInt(cleaned.slice(10, 12), 10);
      return Date.UTC(year, month, day, hour, min, sec);
    } else if (tag === 0x18) {
      // GeneralizedTime: YYYYMMDDHHMMSSZ
      const cleaned = str.replace(/Z$/i, '');
      if (cleaned.length < 14) return null;
      const year = parseInt(cleaned.slice(0, 4), 10);
      const month = parseInt(cleaned.slice(4, 6), 10) - 1;
      const day = parseInt(cleaned.slice(6, 8), 10);
      const hour = parseInt(cleaned.slice(8, 10), 10);
      const min = parseInt(cleaned.slice(10, 12), 10);
      const sec = parseInt(cleaned.slice(12, 14), 10);
      return Date.UTC(year, month, day, hour, min, sec);
    }
    return null;
  } catch {
    return null;
  }
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

/**
 * 认证命名空间 — 提供 AID 注册、登录认证等高级操作。
 * 通过 AUNClient 内部的 AuthFlow 完成完整的 PKI 注册和两阶段认证。
 */
export class AuthNamespace {
  private _client: AUNClient;
  private _log: ModuleLogger = _noopLog;
  private _agentMdCache: Map<string, { text: string; etag: string; lastModified: string }> = new Map();
  setLogger(log: ModuleLogger): void { this._log = log; }

  constructor(client: AUNClient) {
    this._client = client;
  }

  private get _internal(): ClientBridge {
    return this._client as any as ClientBridge;
  }

  /**
   * 解析 gateway URL。
   * 优先使用已预置的 gatewayUrl，否则基于 AID 自动发现。
   *
   * 发现流程：
   * 1. 若 gatewayUrl 已预置（内存），直接返回
   * 2. 从 keystore metadata 读 cached gateway_url（跨进程/会话复用）
   * 3. https://{aid}/.well-known/aun-gateway（泛域名 nameservice）
   * 4. https://gateway.{issuer}/.well-known/aun-gateway（Gateway 直连）
   * 发现成功后写入 keystore metadata，避免每次都做 well-known discovery。
   */
  private async _resolveGateway(aid?: string): Promise<string> {
    if (this._client.gatewayUrl) {
      return this._client.gatewayUrl;
    }

    const resolvedAid = aid ?? this._client.aid;
    if (resolvedAid) {
      // 从 keystore metadata 读持久化的 gateway_url
      try {
        const cached = await this._loadCachedGatewayUrl(resolvedAid);
        if (cached) {
          this._log.debug(`_resolveGateway from keystore cache aid=${resolvedAid} gateway=${cached}`);
          this._client.gatewayUrl = cached;
          return cached;
        }
      } catch (exc) {
        this._log.debug(`_resolveGateway load cache failed: ${exc instanceof Error ? exc.message : String(exc)}`);
      }

      const parts = resolvedAid.split('.');
      const issuerDomain = parts.length > 1 ? parts.slice(1).join('.') : resolvedAid;
      const port = this._client.configModel.discoveryPort;
      const portSuffix = port ? `:${port}` : '';

      // 尝试 nameservice 发现
      const primaryUrl = `https://${resolvedAid}${portSuffix}/.well-known/aun-gateway`;
      try {
        const discovered = await this._client.discovery.discover(primaryUrl);
        await this._persistGatewayUrl(resolvedAid, discovered);
        return discovered;
      } catch {
        // 降级到 Gateway 直连
      }

      const fallbackUrl = `https://gateway.${issuerDomain}${portSuffix}/.well-known/aun-gateway`;
      const discovered = await this._client.discovery.discover(fallbackUrl);
      await this._persistGatewayUrl(resolvedAid, discovered);
      return discovered;
    }

    throw new ValidationError(
      "unable to resolve gateway: set client.gatewayUrl or provide 'aid' for auto-discovery",
    );
  }

  /** 从 keystore metadata 读取 cached gateway_url（跨进程/会话复用） */
  private async _loadCachedGatewayUrl(aid: string): Promise<string> {
    if (!aid) return '';
    const ks = this._internal._keystore;
    if (!ks || typeof ks.getMetadata !== 'function') return '';
    try {
      const value = await ks.getMetadata(aid, 'gateway_url');
      const raw = String(value ?? '').trim();
      if (!raw) return '';
      // 兼容 JSON 编码（Python SDK 通过 save_identity 走 json.dumps）
      // 与裸字符串两种格式：先尝试 JSON.parse，失败则当裸字符串使用
      if (raw.startsWith('"') && raw.endsWith('"')) {
        try {
          const parsed = JSON.parse(raw);
          if (typeof parsed === 'string') return parsed.trim();
        } catch {
          // JSON 解析失败，按裸字符串处理
        }
      }
      return raw;
    } catch {
      return '';
    }
  }

  /** 持久化 gateway_url 到 keystore metadata，供跨进程复用 */
  private async _persistGatewayUrl(aid: string, gatewayUrl: string): Promise<void> {
    if (!gatewayUrl || !aid) return;
    const ks = this._internal._keystore;
    if (!ks || typeof ks.setMetadata !== 'function') return;
    try {
      // JS IndexedDB keystore 的 saveIdentity 把 metadata 字段以原值存储（不 JSON.stringify），
      // setMetadata 也用原值；所以 _persistGatewayUrl 保持原值写入与读取兼容。
      // _loadCachedGatewayUrl 兼容裸字符串和 JSON 编码两种格式。
      await ks.setMetadata(aid, 'gateway_url', gatewayUrl);
    } catch (exc) {
      this._log.debug(`persist gateway_url failed aid=${aid} err=${exc instanceof Error ? exc.message : String(exc)}`);
    }
  }

  /** 内部访问 client 私有属性 */
  /**
   * 严格注册新 AID（对齐 TS registerAid）。
   * 通过 well-known 发现 gateway → 调用 AuthFlow.registerAid 注册。
   */
  async registerAid(params: RpcParams): Promise<AuthNamespaceResult> {
    const tStart = Date.now();
    const aid = String(params?.aid ?? '');
    this._log.debug(`registerAid enter: aid=${aid}`);
    try {
      if (!aid) throw new ValidationError("auth.registerAid requires 'aid'");

      const gatewayUrl = await this._resolveGateway(aid);
      this._client.gatewayUrl = gatewayUrl;

      const auth = this._internal._auth;
      const result = await auth.registerAid(gatewayUrl, aid);
      this._internal._aid = aid;
      this._internal._identity = await auth.loadIdentityOrNone(aid);

      this._log.debug(`registerAid exit: elapsed=${Date.now() - tStart}ms aid=${aid}`);
      return {
        aid: aid,
        cert_pem: result.cert,
        gateway: gatewayUrl,
      };
    } catch (err) {
      this._log.debug(`registerAid exit (error): elapsed=${Date.now() - tStart}ms aid=${aid} err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /**
   * 认证已有 AID（login1 + login2 两阶段认证）。
   * 通过 well-known 发现 gateway → 调用 AuthFlow.authenticate。
   */
  async authenticate(params?: RpcParams): Promise<AuthNamespaceResult> {
    const tStart = Date.now();
    const aid = (params?.aid ?? '') as string;
    this._log.debug(`authenticate enter: aid=${aid || '<current>'}`);
    try {
      const request = { ...(params ?? {}) };
      const requestAid = request.aid as string | undefined;

      const gatewayUrl = await this._resolveGateway(requestAid);
      this._client.gatewayUrl = gatewayUrl;

      const auth = this._internal._auth;
      const result = await auth.authenticate(gatewayUrl, requestAid);
      this._internal._aid = result.aid ?? null;
      this._internal._identity = await auth.loadIdentityOrNone(String(result.aid));

      this._log.debug(`authenticate exit: elapsed=${Date.now() - tStart}ms aid=${result.aid}`);
      return result; // 包含 aid, access_token, refresh_token, expires_at, gateway
    } catch (err) {
      this._log.debug(`authenticate exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  async signAgentMd(content: string, opts?: AgentMdSignOptions): Promise<string> {
    const tStart = Date.now();
    this._log.debug(`signAgentMd enter: aid=${opts?.aid ?? '<current>'} content_len=${String(content ?? '').length}`);
    try {
      const client = this._internal;
      const targetAid = String(opts?.aid ?? client._aid ?? '').trim();
      const identity = await client._auth.loadIdentityOrNone(targetAid || undefined);
      if (!identity) {
        throw new StateError('no local identity found, call auth.registerAid() first');
      }

      const privateKeyPem = String(identity.private_key_pem ?? '').trim();
      const certPem = normalizeIdentityCertPem(identity);
      if (!privateKeyPem || !certPem) {
        throw new StateError('local identity missing private key or certificate');
      }

      let payload = parseAgentMdTailSignature(String(content ?? '')).payload;
      if (payload && !payload.endsWith('\n') && !payload.endsWith('\r')) {
        payload += '\n';
      }

      const privateKey = await importPrivateKeyEcdsa(privateKeyPem);
      const signatureDer = await ecdsaSignDer(privateKey, new TextEncoder().encode(payload));
      const fingerprint = await certificateSha256Fingerprint(certPem);
      if (!fingerprint) {
        throw new StateError('agent.md cert fingerprint failed');
      }

      const signedBlock = [
        AGENT_MD_SIGNATURE_MARKER,
        `cert_fingerprint: ${fingerprint}`,
        `timestamp: ${Math.floor(Date.now() / 1000)}`,
        `signature: ${uint8ToBase64(signatureDer)}`,
        '-->',
      ].join('\n');

      this._log.debug(`signAgentMd exit: elapsed=${Date.now() - tStart}ms aid=${targetAid}`);
      return payload + signedBlock;
    } catch (err) {
      this._log.debug(`signAgentMd exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  async verifyAgentMd(content: string, opts?: AgentMdVerifyOptions): Promise<AgentMdVerifyResult> {
    const tStart = Date.now();
    this._log.debug(`verifyAgentMd enter: aid=${opts?.aid ?? '<infer>'} content_len=${String(content ?? '').length}`);
    try {
      const result = await this._verifyAgentMdImpl(content, opts);
      this._log.debug(`verifyAgentMd exit: elapsed=${Date.now() - tStart}ms status=${result.status} verified=${!!result.verified}`);
      return result;
    } catch (err) {
      this._log.debug(`verifyAgentMd exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  private async _verifyAgentMdImpl(content: string, opts?: AgentMdVerifyOptions): Promise<AgentMdVerifyResult> {
    const { payload, fields, parseError } = parseAgentMdTailSignature(String(content ?? ''));
    if (!fields) {
      if (!parseError) {
        return agentMdResult('unsigned', payload);
      }
      return agentMdResult('invalid', payload, parseError);
    }

    let expectedAid = String(opts?.aid ?? '').trim();
    const payloadAid = extractAgentMDAid(payload);
    if (expectedAid && payloadAid && expectedAid !== payloadAid) {
      return agentMdResult('invalid', payload, 'aid mismatch', payloadAid);
    }
    if (!expectedAid) {
      expectedAid = payloadAid;
    }

    let certPem = String(opts?.certPem ?? opts?.cert_pem ?? '').trim();
    if (!certPem) {
      if (!expectedAid) {
        return agentMdResult('invalid', payload, 'aid required to verify agent.md');
      }
      // 通过 _internal 直接调用，保留 this 绑定（解构后调用会丢失 this，导致 _clientLog 等成员访问失败）
      if (typeof this._internal._fetchPeerCert !== 'function') {
        return agentMdResult('invalid', payload, 'aid required to verify agent.md', expectedAid);
      }
      try {
        certPem = String(await this._internal._fetchPeerCert(expectedAid, fields.cert_fingerprint)).trim();
      } catch (error) {
        return agentMdResult('invalid', payload, String(error), expectedAid, fields.cert_fingerprint);
      }
    }

    let publicKey: CryptoKey;
    try {
      publicKey = await importCertPublicKeyEcdsa(certPem);
    } catch (error) {
      return agentMdResult('invalid', payload, `invalid certificate: ${String(error)}`, expectedAid, fields.cert_fingerprint);
    }

    const actualFingerprint = await certificateSha256Fingerprint(certPem);
    if (!actualFingerprint || actualFingerprint.toLowerCase() !== fields.cert_fingerprint.toLowerCase()) {
      return agentMdResult('invalid', payload, 'certificate fingerprint mismatch', expectedAid, fields.cert_fingerprint);
    }

    const cn = extractCommonNameFromCertPem(certPem);
    if (expectedAid && cn && cn !== expectedAid) {
      return agentMdResult('invalid', payload, 'certificate aid mismatch', expectedAid, fields.cert_fingerprint);
    }

    let signature: Uint8Array;
    try {
      signature = base64ToUint8(fields.signature);
    } catch {
      return agentMdResult('invalid', payload, 'invalid signature', expectedAid, fields.cert_fingerprint);
    }
    if (!signature.length) {
      return agentMdResult('invalid', payload, 'invalid signature', expectedAid, fields.cert_fingerprint);
    }

    const ok = await ecdsaVerifyDer(publicKey, signature, new TextEncoder().encode(payload));
    if (!ok) {
      return agentMdResult('invalid', payload, 'signature verification failed', expectedAid, fields.cert_fingerprint, parseAgentMdTimestamp(fields.timestamp));
    }

    return agentMdResult('verified', payload, '', expectedAid || payloadAid, fields.cert_fingerprint, parseAgentMdTimestamp(fields.timestamp));
  }

  private async _resolveAgentMdUrl(aid: string): Promise<string> {
    const resolvedAid = String(aid ?? '').trim();
    if (!resolvedAid) {
      throw new ValidationError('agent.md requires non-empty aid');
    }
    let gatewayUrl = this._client.gatewayUrl ?? '';
    if (!gatewayUrl) {
      try {
        gatewayUrl = await this._resolveGateway(resolvedAid);
      } catch {
        gatewayUrl = '';
      }
    }
    const authority = agentMdAuthority(resolvedAid, this._client.configModel.discoveryPort);
    return `${agentMdHttpScheme(gatewayUrl)}://${authority}/agent.md`;
  }

  private async _ensureAgentMdUploadToken(aid: string, gatewayUrl: string): Promise<string> {
    const auth = this._internal._auth;

    let identity = await auth.loadIdentityOrNone(aid);
    if (!identity) {
      throw new StateError('no local identity found, call auth.registerAid() first');
    }

    const cachedToken = String(identity.access_token ?? '');
    const expiresAt = auth.getAccessTokenExpiry(identity);
    if (cachedToken && (expiresAt === null || expiresAt > Date.now() / 1000 + 30)) {
      return cachedToken;
    }

    if (typeof auth.refreshCachedTokens === 'function' && identity.refresh_token) {
      try {
        identity = await auth.refreshCachedTokens(gatewayUrl, identity);
        const refreshedToken = String(identity.access_token ?? '');
        const refreshedExpiry = auth.getAccessTokenExpiry(identity);
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
    this._log.debug(`uploadAgentMd enter: content_len=${String(content ?? '').length}`);
    try {
      const auth = this._internal._auth;
      const identity = await auth.loadIdentityOrNone(this._client.aid ?? undefined);
      if (!identity) {
        throw new StateError('no local identity found, call auth.registerAid() first');
      }
      const aid = String(identity.aid ?? this._client.aid ?? '').trim();
      if (!aid) {
        throw new StateError('no local identity found, call auth.registerAid() first');
      }

      const gatewayUrl = await this._resolveGateway(aid);
      this._client.gatewayUrl = gatewayUrl;
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
      });
      const respHeaders = response.headers;
      const etag = respHeaders ? String(respHeaders.get('ETag') ?? '').trim() : '';
      const lastModified = respHeaders ? String(respHeaders.get('Last-Modified') ?? '').trim() : '';
      if (response.status === 404) {
        this._log.debug(`headAgentMd exit (not_found): elapsed=${Date.now() - tStart}ms aid=${targetAid}`);
        return { aid: targetAid, found: false, etag: '', last_modified: '', status: 404 };
      }
      if (response.status < 200 || response.status >= 300) {
        throw new AUNError(`head agent.md failed: HTTP ${response.status}`);
      }
      if (etag || lastModified) {
        const cached = this._agentMdCache.get(targetAid) ?? { text: '', etag: '', lastModified: '' };
        this._agentMdCache.set(targetAid, {
          text: cached.text ?? '',
          etag,
          lastModified,
        });
      }
      this._log.debug(`headAgentMd exit: elapsed=${Date.now() - tStart}ms aid=${targetAid} status=${response.status} etag=${etag || '-'}`);
      return { aid: targetAid, found: true, etag, last_modified: lastModified, status: response.status };
    } catch (err) {
      this._log.debug(`headAgentMd exit (error): elapsed=${Date.now() - tStart}ms aid=${targetAid} err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }
  async downloadAgentMd(aid: string): Promise<string> {
    const tStart = Date.now();
    this._log.debug(`downloadAgentMd enter: aid=${aid}`);
    try {
      const targetAid = String(aid ?? '').trim();
      if (!targetAid) {
        throw new ValidationError('downloadAgentMd requires non-empty aid');
      }
      const cached = this._agentMdCache.get(targetAid);
      const requestHeaders: Record<string, string> = { Accept: 'text/markdown' };
      // 不发送条件请求头，始终做无条件 GET（302 由 fetch 自动跟随）

      const agentMdUrl = await this._resolveAgentMdUrl(targetAid);
      const response = await fetchWithTimeout(agentMdUrl, {
        method: 'GET',
        headers: requestHeaders,
        redirect: 'follow',
      });
      if (response.status === 304) {
        // 304 不应出现（我们不发条件头），但防御性处理
        if (cached?.text) {
          this._log.debug(`downloadAgentMd exit (not_modified): elapsed=${Date.now() - tStart}ms aid=${targetAid}`);
          return cached.text;
        }
        // 本地缓存为空却收到 304，警告并重试无条件 GET
        this._log.warn(`downloadAgentMd got 304 but no local cache, retrying unconditional GET: aid=${targetAid}`);
        const retryResp = await fetchWithTimeout(agentMdUrl, {
          method: 'GET',
          headers: { Accept: 'text/markdown' },
          redirect: 'follow',
        });
        if (retryResp.status === 404) {
          throw new NotFoundError(`agent.md not found for aid: ${targetAid}`);
        }
        if (!retryResp.ok) {
          const message = (await retryResp.text()).trim();
          throw new AUNError(
            `download agent.md failed (retry): HTTP ${retryResp.status}${message ? ` - ${message}` : ''}`,
          );
        }
        const retryText = await retryResp.text();
        this._log.debug(`downloadAgentMd exit (retry): elapsed=${Date.now() - tStart}ms aid=${targetAid} bytes=${retryText.length}`);
        return retryText;
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
      // headers 在某些 fake response（测试 mock）下可能缺失，做一次容错处理。
      const respHeaders = response.headers;
      const etag = respHeaders ? String(respHeaders.get('ETag') ?? '').trim() : '';
      const lastModified = respHeaders ? String(respHeaders.get('Last-Modified') ?? '').trim() : '';
      if (etag || lastModified) {
        this._agentMdCache.set(targetAid, { text, etag, lastModified });
      }
      this._log.debug(`downloadAgentMd exit: elapsed=${Date.now() - tStart}ms aid=${targetAid} bytes=${text.length}`);
      return text;
    } catch (err) {
      this._log.debug(`downloadAgentMd exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 下载证书（透传 RPC） */
  async downloadCert(params?: RpcParams): Promise<RpcResult> {
    const tStart = Date.now();
    this._log.debug('downloadCert enter');
    try {
      const r = await this._client.call('auth.download_cert', params ?? {});
      this._log.debug(`downloadCert exit: elapsed=${Date.now() - tStart}ms`);
      return r;
    } catch (err) {
      this._log.debug(`downloadCert exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 请求签发证书（透传 RPC） */
  async requestCert(params: RpcParams): Promise<RpcResult> {
    const tStart = Date.now();
    this._log.debug('requestCert enter');
    try {
      const r = await this._client.call('auth.request_cert', params);
      this._log.debug(`requestCert exit: elapsed=${Date.now() - tStart}ms`);
      return r;
    } catch (err) {
      this._log.debug(`requestCert exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 续期证书（透传 RPC） */
  async renewCert(params?: RpcParams): Promise<RpcResult> {
    const tStart = Date.now();
    this._log.debug('renewCert enter');
    try {
      const r = await this._client.call('auth.renew_cert', params ?? {});
      this._log.debug(`renewCert exit: elapsed=${Date.now() - tStart}ms`);
      return r;
    } catch (err) {
      this._log.debug(`renewCert exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 密钥轮换（透传 RPC） */
  async rekey(params?: RpcParams): Promise<RpcResult> {
    const tStart = Date.now();
    this._log.debug('rekey enter');
    try {
      const r = await this._client.call('auth.rekey', params ?? {});
      this._log.debug(`rekey exit: elapsed=${Date.now() - tStart}ms`);
      return r;
    } catch (err) {
      this._log.debug(`rekey exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /** 获取信任根（透传 RPC） */
  async trustRoots(params?: RpcParams): Promise<RpcResult> {
    const tStart = Date.now();
    this._log.debug('trustRoots enter');
    try {
      const r = await this._client.call('meta.trust_roots', params ?? {});
      this._log.debug(`trustRoots exit: elapsed=${Date.now() - tStart}ms`);
      return r;
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
      const result = await this._checkLocalAid(aid);
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
      this._log.debug(`checkAid exit: elapsed=${Date.now() - tStart}ms aid=${aid} status=${String(result.status)}`);
      return result;
    } catch (err) {
      this._log.debug(`checkAid exit (error): elapsed=${Date.now() - tStart}ms aid=${aid} err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  private async _checkLocalAid(aid: string): Promise<JsonObject> {
    const client = this._internal;
    const ks = client._keystore;
    const identity = await client._auth.loadIdentityOrNone(aid);

    let keyPair: { private_key_pem?: string; public_key_der_b64?: string } | null = null;
    let keyError = '';
    try {
      if (ks && typeof ks.loadKeyPair === 'function') {
        keyPair = await ks.loadKeyPair(aid);
      }
    } catch (e) {
      keyError = e instanceof Error ? e.message : String(e);
    }

    let certPem: string | null = null;
    let certError = '';
    try {
      if (ks && typeof ks.loadCert === 'function') {
        certPem = await ks.loadCert(aid);
      }
    } catch (e) {
      certError = e instanceof Error ? e.message : String(e);
    }

    const privateKeyPresent = !!(keyPair && keyPair.private_key_pem);
    const publicKeyPresent = !!(keyPair && keyPair.public_key_der_b64);
    const certPresent = !!certPem;
    const certInfo: JsonObject = certPresent
      ? await this._inspectCertBrowser(aid, certPem!)
      : { present: false, valid: false, expired: false };
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

  /** 浏览器环境证书检查（无 node:crypto X509Certificate） */
  private async _inspectCertBrowser(aid: string, certPem: string): Promise<JsonObject> {
    const result: JsonObject = { present: true, valid: false, expired: false };
    try {
      const fingerprint = await certificateSha256Fingerprint(certPem);
      const cn = extractCommonNameFromCertPem(certPem);
      const aidMatches = !cn || cn === aid;

      // 从 DER 解析有效期
      const validity = parseCertValidity(certPem);
      if (validity) {
        const now = Date.now();
        const valid = now >= validity.notBefore && now <= validity.notAfter && aidMatches;
        const expired = now > validity.notAfter;
        result.valid = valid;
        result.expired = expired;
        result.not_before = new Date(validity.notBefore).toISOString();
        result.not_after = new Date(validity.notAfter).toISOString();
        result.expires_at = Math.floor(validity.notAfter / 1000);
        result.seconds_until_expiry = Math.floor((validity.notAfter - now) / 1000);
      } else {
        // 无法解析有效期，仅检查 CN
        result.valid = aidMatches;
      }

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
