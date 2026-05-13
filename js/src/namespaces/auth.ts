// ── AuthNamespace（认证命名空间 — 完整实现）──────────────────

import type { AUNClient } from '../client.js';
import { AUNError, NotFoundError, StateError, ValidationError } from '../errors.js';
import { isJsonObject, type IdentityRecord, type JsonObject, type JsonValue, type RpcParams, type RpcResult } from '../types.js';
import { base64ToUint8, pemToArrayBuffer, uint8ToBase64 } from '../crypto.js';
import {
  _certificateSha256Fingerprint as certificateSha256Fingerprint,
  _ecdsaSignDer as ecdsaSignDer,
  _ecdsaVerifyDer as ecdsaVerifyDer,
  _importCertPublicKeyEcdsa as importCertPublicKeyEcdsa,
  _importPrivateKeyEcdsa as importPrivateKeyEcdsa,
} from '../e2ee.js';

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
  createAid: (url: string, aid: string) => Promise<IdentityRecord>;
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
   * 1. 若 gatewayUrl 已预置，直接返回
   * 2. https://{aid}/.well-known/aun-gateway（泛域名 nameservice）
   * 3. https://gateway.{issuer}/.well-known/aun-gateway（Gateway 直连）
   */
  private async _resolveGateway(aid?: string): Promise<string> {
    if (this._client.gatewayUrl) {
      return this._client.gatewayUrl;
    }

    const resolvedAid = aid ?? this._client.aid;
    if (resolvedAid) {
      const parts = resolvedAid.split('.');
      const issuerDomain = parts.length > 1 ? parts.slice(1).join('.') : resolvedAid;
      const port = this._client.configModel.discoveryPort;
      const portSuffix = port ? `:${port}` : '';

      // 尝试 nameservice 发现
      const primaryUrl = `https://${resolvedAid}${portSuffix}/.well-known/aun-gateway`;
      try {
        return await this._client.discovery.discover(primaryUrl);
      } catch {
        // 降级到 Gateway 直连
      }

      const fallbackUrl = `https://gateway.${issuerDomain}${portSuffix}/.well-known/aun-gateway`;
      return await this._client.discovery.discover(fallbackUrl);
    }

    throw new ValidationError(
      "unable to resolve gateway: set client.gatewayUrl or provide 'aid' for auto-discovery",
    );
  }

  /** 内部访问 client 私有属性 */
  /**
   * 注册新 AID。
   * 通过 well-known 发现 gateway → 调用 AuthFlow.createAid 注册。
   */
  async createAid(params: RpcParams): Promise<AuthNamespaceResult> {
    const aid = String(params?.aid ?? '');
    if (!aid) throw new ValidationError("auth.createAid requires 'aid'");

    const gatewayUrl = await this._resolveGateway(aid);
    this._client.gatewayUrl = gatewayUrl;

    const auth = this._internal._auth;
    const result = await auth.createAid(gatewayUrl, aid);
    this._internal._aid = result.aid ?? null;
    this._internal._identity = await auth.loadIdentityOrNone(String(result.aid));

    return {
      aid: result.aid,
      cert_pem: result.cert,
      gateway: gatewayUrl,
    };
  }

  /**
   * 认证已有 AID（login1 + login2 两阶段认证）。
   * 通过 well-known 发现 gateway → 调用 AuthFlow.authenticate。
   */
  async authenticate(params?: RpcParams): Promise<AuthNamespaceResult> {
    const request = { ...(params ?? {}) };
    const aid = request.aid as string | undefined;

    const gatewayUrl = await this._resolveGateway(aid);
    this._client.gatewayUrl = gatewayUrl;

    const auth = this._internal._auth;
    const result = await auth.authenticate(gatewayUrl, aid);
    this._internal._aid = result.aid ?? null;
    this._internal._identity = await auth.loadIdentityOrNone(String(result.aid));

    return result; // 包含 aid, access_token, refresh_token, expires_at, gateway
  }

  async signAgentMd(content: string, opts?: AgentMdSignOptions): Promise<string> {
    const client = this._internal;
    const targetAid = String(opts?.aid ?? client._aid ?? '').trim();
    const identity = await client._auth.loadIdentityOrNone(targetAid || undefined);
    if (!identity) {
      throw new StateError('no local identity found, call auth.createAid() first');
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

    return payload + signedBlock;
  }

  async verifyAgentMd(content: string, opts?: AgentMdVerifyOptions): Promise<AgentMdVerifyResult> {
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
      const fetchPeerCert = this._internal._fetchPeerCert;
      if (typeof fetchPeerCert !== 'function') {
        return agentMdResult('invalid', payload, 'aid required to verify agent.md', expectedAid);
      }
      try {
        certPem = String(await fetchPeerCert(expectedAid, fields.cert_fingerprint)).trim();
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
      throw new StateError('no local identity found, call auth.createAid() first');
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
    const auth = this._internal._auth;
    const identity = await auth.loadIdentityOrNone(this._client.aid ?? undefined);
    if (!identity) {
      throw new StateError('no local identity found, call auth.createAid() first');
    }
    const aid = String(identity.aid ?? this._client.aid ?? '').trim();
    if (!aid) {
      throw new StateError('no local identity found, call auth.createAid() first');
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
    return payload;
  }

  async downloadAgentMd(aid: string): Promise<string> {
    const targetAid = String(aid ?? '').trim();
    if (!targetAid) {
      throw new ValidationError('downloadAgentMd requires non-empty aid');
    }
    const response = await fetchWithTimeout(await this._resolveAgentMdUrl(targetAid), {
      method: 'GET',
      headers: {
        Accept: 'text/markdown',
      },
    });
    if (response.status === 404) {
      throw new NotFoundError(`agent.md not found for aid: ${targetAid}`);
    }
    if (!response.ok) {
      const message = (await response.text()).trim();
      throw new AUNError(
        `download agent.md failed: HTTP ${response.status}${message ? ` - ${message}` : ''}`,
      );
    }
    return await response.text();
  }

  /** 下载证书（透传 RPC） */
  async downloadCert(params?: RpcParams): Promise<RpcResult> {
    return this._client.call('auth.download_cert', params ?? {});
  }

  /** 请求签发证书（透传 RPC） */
  async requestCert(params: RpcParams): Promise<RpcResult> {
    return this._client.call('auth.request_cert', params);
  }

  /** 续期证书（透传 RPC） */
  async renewCert(params?: RpcParams): Promise<RpcResult> {
    return this._client.call('auth.renew_cert', params ?? {});
  }

  /** 密钥轮换（透传 RPC） */
  async rekey(params?: RpcParams): Promise<RpcResult> {
    return this._client.call('auth.rekey', params ?? {});
  }

  /** 获取信任根（透传 RPC） */
  async trustRoots(params?: RpcParams): Promise<RpcResult> {
    return this._client.call('meta.trust_roots', params ?? {});
  }
}
