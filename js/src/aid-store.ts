import { AID } from './aid.js';
import { CryptoProvider, pemToArrayBuffer, importPrivateKeyEcdsa, importCertPublicKeyEcdsa, ecdsaSignDer, ecdsaVerifyDer } from './crypto.js';
import * as codes from './error-codes.js';
import { publicKeyDerB64 } from './cert-utils.js';
import { AuthFlow } from './auth.js';
import { GatewayDiscovery } from './discovery.js';
import { IdentityConflictError, ValidationError } from './errors.js';
import { IndexedDBKeyStore } from './keystore/indexeddb.js';
import { getDeviceId, normalizeInstanceId } from './config.js';
import type { IdentityRecord, JsonObject } from './types.js';
import { resultErr, resultOk, type Result } from './result.js';

export interface AIDInfo {
  aid: string;
  certFingerprint: string;
  certNotAfter: Date;
  certIssuer: string;
}

export interface ResolveOpts {
  forceRefresh?: boolean;
  timeout?: number;
  skipAgentMd?: boolean;
}

interface AgentMdCacheEntry {
  content?: string;
  etag?: string;
  lastModified?: string;
  updatedAt?: number;
}

// ── 证书 DER 解析工具 ────────────────────────────────────────────

function _derReadLength(data: Uint8Array, offset: number): { value: number; lenBytes: number } | null {
  if (offset >= data.length) return null;
  const first = data[offset]!;
  if (first < 0x80) return { value: first, lenBytes: 1 };
  const n = first & 0x7f;
  if (n === 0 || n > 4) return null;
  let v = 0;
  for (let i = 0; i < n; i++) v = (v << 8) | data[offset + 1 + i]!;
  return { value: v, lenBytes: 1 + n };
}

function _derSkipTlv(data: Uint8Array, offset: number): number | null {
  const len = _derReadLength(data, offset + 1);
  if (!len) return null;
  return offset + 1 + len.lenBytes + len.value;
}

/**
 * 从证书 PEM 中提取有效期 [notBefore, notAfter]（Unix ms）。
 * 仅支持 UTCTime（0x17）和 GeneralizedTime（0x18）。
 */
function parseCertValidity(certPem: string): { notBefore: number; notAfter: number } | null {
  try {
    const der = new Uint8Array(pemToArrayBuffer(certPem));
    // SEQUENCE (cert) → SEQUENCE (tbs) → skip version/serial/sigAlg/issuer → SEQUENCE (validity)
    const cert = _derSkipTlv(der, -1); // 先找 cert SEQUENCE 起点
    // 直接从 offset=0 开始解析
    const certLen = _derReadLength(der, 1);
    if (!certLen || der[0] !== 0x30) return null;
    const tbsStart = 1 + certLen.lenBytes;
    if (der[tbsStart] !== 0x30) return null;
    const tbsLen = _derReadLength(der, tbsStart + 1);
    if (!tbsLen) return null;
    let pos = tbsStart + 1 + tbsLen.lenBytes;
    // 跳过 [0] version（可选）
    if (der[pos] === 0xa0) { const e = _derSkipTlv(der, pos); if (e === null) return null; pos = e; }
    // 跳过 serialNumber
    { const e = _derSkipTlv(der, pos); if (e === null) return null; pos = e; }
    // 跳过 signature AlgId
    { const e = _derSkipTlv(der, pos); if (e === null) return null; pos = e; }
    // 跳过 issuer
    { const e = _derSkipTlv(der, pos); if (e === null) return null; pos = e; }
    // 现在 pos 指向 validity SEQUENCE
    if (der[pos] !== 0x30) return null;
    const valLen = _derReadLength(der, pos + 1);
    if (!valLen) return null;
    pos = pos + 1 + valLen.lenBytes;

    function parseTime(offset: number): number | null {
      const tag = der[offset];
      const len = _derReadLength(der, offset + 1);
      if (!len) return null;
      const raw = new TextDecoder().decode(der.slice(offset + 1 + len.lenBytes, offset + 1 + len.lenBytes + len.value));
      if (tag === 0x17) {
        // UTCTime: YYMMDDHHMMSSZ
        const y = parseInt(raw.slice(0, 2), 10);
        const year = y >= 50 ? 1900 + y : 2000 + y;
        return Date.UTC(year, parseInt(raw.slice(2, 4), 10) - 1, parseInt(raw.slice(4, 6), 10),
          parseInt(raw.slice(6, 8), 10), parseInt(raw.slice(8, 10), 10), parseInt(raw.slice(10, 12), 10));
      } else if (tag === 0x18) {
        // GeneralizedTime: YYYYMMDDHHMMSSZ
        return Date.UTC(parseInt(raw.slice(0, 4), 10), parseInt(raw.slice(4, 6), 10) - 1, parseInt(raw.slice(6, 8), 10),
          parseInt(raw.slice(8, 10), 10), parseInt(raw.slice(10, 12), 10), parseInt(raw.slice(12, 14), 10));
      }
      return null;
    }

    const notBefore = parseTime(pos);
    if (notBefore === null) return null;
    const nbLen = _derReadLength(der, pos + 1);
    if (!nbLen) return null;
    const notAfterOffset = pos + 1 + nbLen.lenBytes + nbLen.value;
    const notAfter = parseTime(notAfterOffset);
    if (notAfter === null) return null;
    return { notBefore, notAfter };
  } catch {
    return null;
  }
}

/**
 * 从证书 PEM 中提取 subject CN。
 * 返回 null 表示无法解析（不视为错误，跳过 CN 校验）。
 */
function parseCertCN(certPem: string): string | null {
  try {
    const der = new Uint8Array(pemToArrayBuffer(certPem));
    if (der[0] !== 0x30) return null;
    const certLen = _derReadLength(der, 1);
    if (!certLen) return null;
    const tbsStart = 1 + certLen.lenBytes;
    if (der[tbsStart] !== 0x30) return null;
    const tbsLen = _derReadLength(der, tbsStart + 1);
    if (!tbsLen) return null;
    let pos = tbsStart + 1 + tbsLen.lenBytes;
    if (der[pos] === 0xa0) { const e = _derSkipTlv(der, pos); if (e === null) return null; pos = e; }
    { const e = _derSkipTlv(der, pos); if (e === null) return null; pos = e; } // serial
    { const e = _derSkipTlv(der, pos); if (e === null) return null; pos = e; } // sigAlg
    // issuer SEQUENCE
    if (der[pos] !== 0x30) return null;
    const issuerLen = _derReadLength(der, pos + 1);
    if (!issuerLen) return null;
    const issuerEnd = pos + 1 + issuerLen.lenBytes + issuerLen.value;
    pos = pos + 1 + issuerLen.lenBytes;
    // 跳过 issuer，找 subject（在 validity 之后）
    // 先跳过 issuer
    pos = issuerEnd;
    // 跳过 validity
    { const e = _derSkipTlv(der, pos); if (e === null) return null; pos = e; }
    // 现在 pos 指向 subject SEQUENCE
    if (der[pos] !== 0x30) return null;
    const subjectLen = _derReadLength(der, pos + 1);
    if (!subjectLen) return null;
    const subjectEnd = pos + 1 + subjectLen.lenBytes + subjectLen.value;
    pos = pos + 1 + subjectLen.lenBytes;
    // 遍历 subject RDN SET
    while (pos < subjectEnd) {
      if (der[pos] !== 0x31) break; // SET
      const setLen = _derReadLength(der, pos + 1);
      if (!setLen) break;
      const setEnd = pos + 1 + setLen.lenBytes + setLen.value;
      let rpos = pos + 1 + setLen.lenBytes;
      while (rpos < setEnd) {
        if (der[rpos] !== 0x30) break; // SEQUENCE
        const seqLen = _derReadLength(der, rpos + 1);
        if (!seqLen) break;
        const seqEnd = rpos + 1 + seqLen.lenBytes + seqLen.value;
        let apos = rpos + 1 + seqLen.lenBytes;
        // OID
        if (der[apos] !== 0x06) { rpos = seqEnd; continue; }
        const oidLen = _derReadLength(der, apos + 1);
        if (!oidLen) { rpos = seqEnd; continue; }
        const oidBytes = der.slice(apos + 1 + oidLen.lenBytes, apos + 1 + oidLen.lenBytes + oidLen.value);
        // CN OID: 2.5.4.3 = 55 04 03
        const isCN = oidBytes.length === 3 && oidBytes[0] === 0x55 && oidBytes[1] === 0x04 && oidBytes[2] === 0x03;
        apos = apos + 1 + oidLen.lenBytes + oidLen.value;
        if (isCN && apos < seqEnd) {
          const valLen = _derReadLength(der, apos + 1);
          if (valLen) {
            return new TextDecoder().decode(der.slice(apos + 1 + valLen.lenBytes, apos + 1 + valLen.lenBytes + valLen.value));
          }
        }
        rpos = seqEnd;
      }
      pos = setEnd;
    }
    return null;
  } catch {
    return null;
  }
}

function normalizeSlotId(slotId?: string): string {
  const value = String(slotId ?? 'default').trim();
  return value || 'default';
}

function issuerFromAid(aid: string): string {
  const target = String(aid ?? '').trim();
  const dotIdx = target.indexOf('.');
  return dotIdx >= 0 ? target.slice(dotIdx + 1) : target;
}

function validateRegisterAidName(aid: string): void {
  if (!aid) throw new ValidationError("AIDStore.register requires 'aid'");
  const name = aid.includes('.') ? aid.split('.')[0] : aid;
  if (!/^[a-z0-9_][a-z0-9_-]{3,63}$/.test(name)) {
    throw new ValidationError(
      `Invalid AID name '${name}': must be 4-64 characters, only [a-z0-9_-], cannot start with '-'`,
    );
  }
  if (name.startsWith('guest')) {
    throw new ValidationError("AID name must not start with 'guest'");
  }
}

function gatewayHttpUrl(gatewayUrl: string, path: string): string {
  const parsed = new URL(gatewayUrl);
  parsed.protocol = parsed.protocol === 'wss:' ? 'https:' : 'http:';
  parsed.pathname = path;
  parsed.search = '';
  parsed.hash = '';
  return parsed.toString();
}

function pkiCertUrl(gatewayUrl: string, aid: string): string {
  return gatewayHttpUrl(gatewayUrl, `/pki/cert/${encodeURIComponent(aid)}`);
}

function agentMdUrl(aid: string, gatewayUrl: string, discoveryPort?: number | null): string {
  const scheme = String(gatewayUrl ?? '').trim().toLowerCase().startsWith('ws://') ? 'http' : 'https';
  let host = String(aid ?? '').trim();
  if (discoveryPort && !host.includes(':')) host = `${host}:${discoveryPort}`;
  return `${scheme}://${host}/agent.md`;
}

async function fetchWithTimeout(input: string, init: RequestInit = {}, timeoutMs = 30000): Promise<Response> {
  const controller = new AbortController();
  const timer = globalThis.setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(input, { ...init, signal: controller.signal });
  } finally {
    globalThis.clearTimeout(timer);
  }
}

function resultError<T>(result: Result<T>): { code: string; message: string } | null {
  return result.ok ? null : result.error;
}

export class AIDStore {
  readonly aunPath: string;
  readonly deviceId: string;
  readonly slotId: string;

  private _encryptionSeed: string;
  private _keystore: IndexedDBKeyStore;
  private _auth: AuthFlow;
  private _crypto: CryptoProvider;
  private _discovery: GatewayDiscovery;
  private _verifySsl: boolean;
  private _discoveryPort: number | null;
  private _gatewayCache: Map<string, string> = new Map();
  private _agentMdCache: Map<string, AgentMdCacheEntry> = new Map();

  constructor(opts: {
    aunPath: string;
    encryptionSeed: string;
    deviceId?: string;
    slotId?: string;
    rootCaPem?: string | null;
    verifySsl?: boolean;
    discoveryPort?: number | null;
  }) {
    this.aunPath = String(opts.aunPath ?? '');
    this._encryptionSeed = String(opts.encryptionSeed ?? '');
    this.deviceId = opts.deviceId
      ? normalizeInstanceId(opts.deviceId, 'deviceId', { allowEmpty: true })
      : getDeviceId();
    this.slotId = normalizeSlotId(opts.slotId);
    this._verifySsl = opts.verifySsl ?? true;
    this._discoveryPort = opts.discoveryPort ?? null;
    this._keystore = new IndexedDBKeyStore({ encryptionSeed: this._encryptionSeed || undefined });
    this._crypto = new CryptoProvider();
    this._discovery = new GatewayDiscovery();
    this._auth = new AuthFlow({
      keystore: this._keystore,
      crypto: this._crypto,
      deviceId: this.deviceId,
      slotId: this.slotId,
      rootCaPem: opts.rootCaPem ?? null,
      verifySsl: this._verifySsl,
    });
  }

  close(): void {
    const close = (this._keystore as unknown as { close?: () => void }).close;
    if (typeof close === 'function') close.call(this._keystore);
  }

  async load(aid: string): Promise<Result<{ aid: AID }>> {
    const target = String(aid ?? '').trim();
    const certPem = await this._keystore.loadCert(target);
    if (!certPem) return resultErr(codes.CERT_NOT_FOUND, `certificate not found for aid: ${target}`);

    // 证书基础解析
    let certPub = '';
    try {
      certPub = publicKeyDerB64(certPem);
      if (!certPub) return resultErr(codes.CERT_PARSE_ERROR, `certificate parse failed for aid: ${target}`);
    } catch (exc) {
      return resultErr(codes.CERT_PARSE_ERROR, `certificate parse failed for aid: ${target}`, exc);
    }

    // 有效期检查（对齐 Python cert_time_error）
    const validity = parseCertValidity(certPem);
    if (validity) {
      const now = Date.now();
      if (now > validity.notAfter) {
        return resultErr(codes.CERT_EXPIRED, `certificate expired for aid: ${target}`);
      }
      if (now < validity.notBefore) {
        return resultErr(codes.CERT_NOT_YET_VALID, `certificate not yet valid for aid: ${target}`);
      }
    }

    // CN 校验（对齐 Python cert_common_name 检查）
    const cn = parseCertCN(certPem);
    if (cn && cn !== target) {
      return resultErr(codes.CERT_CHAIN_BROKEN, `certificate CN mismatch: expected ${target}, got ${cn}`);
    }

    // 加载私钥
    let keyPair: { private_key_pem?: string; public_key_der_b64?: string } | null;
    try {
      keyPair = await this._keystore.loadKeyPair(target);
    } catch (exc) {
      return resultErr(codes.PRIVATE_KEY_PARSE_ERROR, `private key load failed for aid: ${target}`, exc);
    }

    if (!keyPair?.private_key_pem) {
      return resultOk({
        aid: await AID.create({
          aid: target,
          aunPath: this.aunPath,
          certPem,
          privateKeyPem: null,
          certValid: true,
          privateKeyValid: false,
          deviceId: this.deviceId,
          slotId: this.slotId,
        }),
      });
    }

    // 私钥解析 + 配对自检（对齐 Python sign/verify probe）
    try {
      const privateKey = await importPrivateKeyEcdsa(String(keyPair.private_key_pem));
      // public_key_der_b64 字段存在时做快速比对
      if (keyPair.public_key_der_b64 && keyPair.public_key_der_b64 !== certPub) {
        return resultErr(codes.KEYPAIR_MISMATCH, `keypair public key mismatch for aid: ${target}`);
      }
      // sign/verify 自检：用私钥签名探针，用证书公钥验证
      const probe = new TextEncoder().encode('aun-aidstore-private-key-self-test');
      const sig = await ecdsaSignDer(privateKey, probe);
      const pubKey = await importCertPublicKeyEcdsa(certPem);
      const ok = await ecdsaVerifyDer(pubKey, sig, probe);
      if (!ok) {
        return resultErr(codes.KEYPAIR_MISMATCH, `private key does not match certificate for aid: ${target}`);
      }
    } catch (exc) {
      return resultErr(codes.PRIVATE_KEY_PARSE_ERROR, `private key parse failed for aid: ${target}`, exc);
    }

    return resultOk({
      aid: await AID.create({
        aid: target,
        aunPath: this.aunPath,
        certPem,
        privateKeyPem: String(keyPair.private_key_pem),
        certValid: true,
        privateKeyValid: true,
        deviceId: this.deviceId,
        slotId: this.slotId,
      }),
    });
  }

  async list(): Promise<Result<{ identities: AIDInfo[] }>> {
    try {
      const aids = await this._keystore.listIdentities();
      const identities: AIDInfo[] = [];
      for (const aid of aids.sort()) {
        const loaded = await this.load(aid);
        if (loaded.ok && loaded.data.aid.isPrivateKeyValid()) {
          identities.push({
            aid: loaded.data.aid.aid,
            certFingerprint: loaded.data.aid.certFingerprint,
            certNotAfter: loaded.data.aid.certNotAfter,
            certIssuer: loaded.data.aid.certIssuer,
          });
        }
      }
      return resultOk({ identities });
    } catch (exc) {
      return resultErr('LIST_IDENTITIES_FAILED', String(exc), exc);
    }
  }

  async changeSeed(oldSeed: string, newSeed: string): Promise<Result<{ changed: boolean; count: number }>> {
    try {
      const changed = await this._keystore.changeSeed?.(oldSeed, newSeed);
      this._encryptionSeed = String(newSeed ?? '');
      return resultOk({ changed: true, count: changed?.privateKeysMigrated ?? changed?.migrated ?? 0 });
    } catch (exc) {
      return resultErr(codes.PRIVATE_KEY_PARSE_ERROR, String(exc), exc);
    }
  }

  async register(aid: string): Promise<Result<{ registered: true }>> {
    const target = String(aid ?? '').trim();
    try {
      validateRegisterAidName(target);
      const gatewayUrl = await this._resolveGateway(target);
      await this._auth.registerAid(gatewayUrl, target);
      return resultOk({ registered: true as const });
    } catch (exc) {
      if (exc instanceof IdentityConflictError) {
        return resultErr(codes.IDENTITY_CONFLICT, String(exc), exc);
      }
      if (exc instanceof ValidationError) {
        return resultErr(codes.INVALID_AID_FORMAT, String(exc), exc);
      }
      const message = exc instanceof Error ? exc.message : String(exc);
      if (/network|connect|timeout|abort/i.test(message)) {
        return resultErr(codes.NETWORK_ERROR, message, exc);
      }
      return resultErr(codes.SERVER_ERROR, message, exc);
    }
  }

  async exists(aid: string): Promise<Result<{ exists: boolean }>> {
    const target = String(aid ?? '').trim();
    try {
      const gatewayUrl = await this._resolveGateway(target);
      const response = await fetchWithTimeout(pkiCertUrl(gatewayUrl, target), { method: 'HEAD' }, 10000);
      if (response.status === 200) return resultOk({ exists: true });
      if (response.status === 404) return resultOk({ exists: false });
      return resultErr(codes.NETWORK_ERROR, `unexpected PKI HEAD status ${response.status}`);
    } catch (exc) {
      return resultErr(codes.NETWORK_ERROR, String(exc), exc);
    }
  }

  async resolve(aid: string, opts?: ResolveOpts): Promise<Result<Record<string, unknown>>> {
    const target = String(aid ?? '').trim();
    const forceRefresh = !!opts?.forceRefresh;
    const skipAgentMd = !!opts?.skipAgentMd;
    try {
      let peer: AID;
      let certFromCache = false;
      const cached = await this.load(target);
      if (cached.ok && !forceRefresh) {
        peer = cached.data.aid;
        certFromCache = true;
      } else {
        const gatewayUrl = await this._resolveGateway(target);
        const certPem = await this._auth.fetchPeerCert(gatewayUrl, target);
        if (!certPem) return resultErr(codes.CERT_NOT_FOUND, `certificate not found for aid: ${target}`);
        await this._keystore.saveCert(target, certPem);
        const reloaded = await this.load(target);
        if (!reloaded.ok) return reloaded as Result<never>;
        peer = reloaded.data.aid;
      }

      const source = { certFromCache, cert_from_cache: certFromCache, agentMdFetched: false, agent_md_fetched: false };
      if (skipAgentMd) return resultOk({ aid: peer, source });

      const agentMd = await this.fetchAgentMd(target);
      if (!agentMd.ok) return agentMd as Result<never>;
      source.agentMdFetched = true;
      source.agent_md_fetched = true;
      return resultOk({ aid: peer, agentMd: agentMd.data, agent_md: agentMd.data, source });
    } catch (exc) {
      return resultErr(codes.NETWORK_ERROR, String(exc), exc);
    }
  }

  async fetchAgentMd(aid: string): Promise<Result<Record<string, unknown>>> {
    const target = String(aid ?? '').trim();
    try {
      const gatewayUrl = await this._resolveGateway(target);
      const cached = this._agentMdCache.get(target) ?? {};
      const headers: Record<string, string> = { Accept: 'text/markdown' };
      if (cached.etag) headers['If-None-Match'] = cached.etag;
      if (cached.lastModified) headers['If-Modified-Since'] = cached.lastModified;

      const response = await fetchWithTimeout(agentMdUrl(target, gatewayUrl, this._discoveryPort), {
        method: 'GET',
        headers,
      }, 30000);

      let content = '';
      if (response.status === 304 && cached.content) {
        content = cached.content;
      } else if (response.status === 404) {
        return resultErr(codes.AGENTMD_NOT_FOUND, `agent.md not found for aid: ${target}`);
      } else if (!response.ok) {
        return resultErr(codes.NETWORK_ERROR, `download agent.md failed: HTTP ${response.status}`);
      } else {
        content = await response.text();
      }

      let peer: AID;
      const loaded = await this.load(target);
      if (loaded.ok) {
        peer = loaded.data.aid;
      } else {
        const resolved = await this.resolve(target, { skipAgentMd: true });
        if (!resolved.ok) return resolved as Result<never>;
        peer = resolved.data.aid as AID;
      }

      const verified = await peer.verifyAgentMd(content);
      if (!verified.ok) return verified as Result<never>;
      const signature = verified.data;
      const verification: Record<string, string> = { status: signature.status };
      if (signature.reason) verification.reason = signature.reason;

      const etag = String(response.headers?.get('ETag') ?? response.headers?.get('etag') ?? cached.etag ?? '').trim();
      const lastModified = String(response.headers?.get('Last-Modified') ?? response.headers?.get('last-modified') ?? cached.lastModified ?? '').trim();
      this._agentMdCache.set(target, { content, etag, lastModified, updatedAt: Date.now() });
      return resultOk({
        aid: target,
        content,
        verification,
        signature,
        certPem: peer.certPem,
        cert_pem: peer.certPem,
        etag,
        lastModified,
        last_modified: lastModified,
        status: response.status,
      });
    } catch (exc) {
      return resultErr(codes.NETWORK_ERROR, String(exc), exc);
    }
  }

  async headAgentMd(aid: string): Promise<Result<Record<string, unknown>>> {
    const target = String(aid ?? '').trim();
    try {
      const gatewayUrl = await this._resolveGateway(target);
      const response = await fetchWithTimeout(agentMdUrl(target, gatewayUrl, this._discoveryPort), {
        method: 'HEAD',
        headers: { Accept: 'text/markdown' },
      }, 15000);
      if (response.status === 404) {
        return resultErr(codes.AGENTMD_NOT_FOUND, `agent.md not found for aid: ${target}`);
      }
      if (!response.ok) {
        return resultErr(codes.NETWORK_ERROR, `head agent.md failed: HTTP ${response.status}`);
      }
      const etag = String(response.headers?.get('ETag') ?? response.headers?.get('etag') ?? '').trim();
      const lastModified = String(response.headers?.get('Last-Modified') ?? response.headers?.get('last-modified') ?? '').trim();
      const contentLength = Number.parseInt(String(response.headers?.get('Content-Length') ?? response.headers?.get('content-length') ?? '0'), 10) || 0;
      const cached = this._agentMdCache.get(target) ?? {};
      this._agentMdCache.set(target, { ...cached, etag, lastModified, updatedAt: Date.now() });
      return resultOk({
        aid: target,
        found: true,
        etag,
        lastModified,
        last_modified: lastModified,
        contentLength,
        content_length: contentLength,
        status: response.status,
      });
    } catch (exc) {
      return resultErr(codes.NETWORK_ERROR, String(exc), exc);
    }
  }

  async checkAgentMd(aid: string, ttlDays = 1): Promise<Result<Record<string, unknown>>> {
    const target = String(aid ?? '').trim();
    const cached = this._agentMdCache.get(target) ?? {};
    const head = await this.headAgentMd(target);
    let remote: Record<string, unknown>;
    if (!head.ok) {
      if (head.error.code === codes.AGENTMD_NOT_FOUND) {
        remote = { aid: target, found: false, etag: '', last_modified: '', content_length: 0, status: 404 };
      } else {
        return head as Result<never>;
      }
    } else {
      remote = head.data;
    }

    const localEtag = String(cached.etag ?? '').trim();
    const localFound = !!cached.content;
    const remoteFound = !!remote.found;
    const remoteEtag = String(remote.etag ?? '').trim();
    const needsUpdate = remoteFound && (!localFound || (!!remoteEtag && remoteEtag !== localEtag));
    return resultOk({
      aid: target,
      localFound,
      local_found: localFound,
      remoteFound,
      remote_found: remoteFound,
      localEtag,
      local_etag: localEtag,
      remoteEtag,
      remote_etag: remoteEtag,
      lastModified: String(remote.lastModified ?? remote.last_modified ?? ''),
      last_modified: String(remote.last_modified ?? remote.lastModified ?? ''),
      needsUpdate,
      needs_update: needsUpdate,
      ttlDays,
      ttl_days: ttlDays,
    });
  }

  async diagnose(aid: string): Promise<Result<Record<string, unknown>>> {
    const target = String(aid ?? '').trim();
    const loaded = await this.load(target);
    const remote = await this.exists(target);
    const remoteError = resultError(remote);
    const localError = resultError(loaded);
    const localAid = loaded.ok ? loaded.data.aid : null;
    const localCert = !!localAid?.isCertValid();
    const localPrivateKey = !!localAid?.isPrivateKeyValid();
    const localValid = localCert && localPrivateKey;
    const remoteRegistered = !!(remote.ok && remote.data.exists);
    const suggestions: string[] = [];
    if (!localPrivateKey) suggestions.push('load or register a local identity with a valid private key');
    if (!remoteRegistered) suggestions.push('register the AID before using it on the network');
    if (remoteError) suggestions.push(`remote registration check failed: ${remoteError.message}`);
    const status = localPrivateKey && remoteRegistered
      ? 'ready'
      : remoteRegistered
        ? 'registered_remote'
        : remote.ok
          ? 'available'
          : 'unknown';
    return resultOk({
      aid: target,
      status,
      localValid,
      local_valid: localValid,
      remoteRegistered,
      remote_registered: remoteRegistered,
      suggestions,
      local: { cert: localCert, private_key: localPrivateKey, error: localError },
      remote: { checked: remote.ok, exists: remote.ok ? remoteRegistered : null, error: remoteError },
    });
  }

  async renewCert(aid: string): Promise<Result<Record<string, unknown>>> {
    const target = String(aid ?? '').trim();
    const loaded = await this.load(target);
    if (!loaded.ok || !loaded.data.aid.isPrivateKeyValid()) {
      return resultErr(codes.PRIVATE_KEY_REQUIRED, `private key required for aid: ${target}`);
    }
    try {
      const identity = await this._auth.loadIdentityOrNone(target);
      if (!identity?.cert || !identity.private_key_pem) {
        return resultErr(codes.PRIVATE_KEY_REQUIRED, `private key required for aid: ${target}`);
      }
      const gatewayUrl = await this._resolveGateway(target);
      const clientNonce = this._crypto.newClientNonce();
      const phase1 = await (this._auth as unknown as { _shortRpc: (url: string, method: string, params: JsonObject) => Promise<JsonObject> })
        ._shortRpc(gatewayUrl, 'auth.aid_login1', {
          aid: target,
          cert: identity.cert,
          client_nonce: clientNonce,
        });
      const [signature, clientTime] = await this._crypto.signLoginNonce(identity.private_key_pem, String(phase1.nonce ?? ''));
      const response = await (this._auth as unknown as { _shortRpc: (url: string, method: string, params: JsonObject) => Promise<JsonObject> })
        ._shortRpc(gatewayUrl, 'auth.renew_cert', {
          aid: target,
          request_id: String(phase1.request_id ?? ''),
          nonce: String(phase1.nonce ?? ''),
          client_time: clientTime,
          signature,
        });
      const certPem = String(response.cert ?? response.cert_pem ?? '').trim();
      if (!certPem) return resultErr(codes.CERT_RENEWAL_FAILED, 'server response missing certificate');
      await this._keystore.saveCert(target, certPem);
      const refreshed = await this.load(target);
      if (!refreshed.ok) return resultErr(codes.CERT_RENEWAL_FAILED, 'renewed certificate reload failed');
      return resultOk({
        renewed: true,
        newFingerprint: refreshed.data.aid.certFingerprint,
        new_fingerprint: refreshed.data.aid.certFingerprint,
      });
    } catch (exc) {
      return resultErr(codes.CERT_RENEWAL_FAILED, String(exc), exc);
    }
  }

  async rekey(aid: string): Promise<Result<Record<string, unknown>>> {
    const target = String(aid ?? '').trim();
    const loaded = await this.load(target);
    if (!loaded.ok || !loaded.data.aid.isPrivateKeyValid()) {
      return resultErr(codes.PRIVATE_KEY_REQUIRED, `private key required for aid: ${target}`);
    }
    try {
      const identity = await this._auth.loadIdentityOrNone(target);
      if (!identity?.cert || !identity.private_key_pem) {
        return resultErr(codes.PRIVATE_KEY_REQUIRED, `private key required for aid: ${target}`);
      }
      const gatewayUrl = await this._resolveGateway(target);
      const newIdentity = await this._crypto.generateIdentity();
      const clientNonce = this._crypto.newClientNonce();
      const phase1 = await (this._auth as unknown as { _shortRpc: (url: string, method: string, params: JsonObject) => Promise<JsonObject> })
        ._shortRpc(gatewayUrl, 'auth.aid_login1', {
          aid: target,
          cert: identity.cert,
          client_nonce: clientNonce,
        });
      const signPayload = `${String(phase1.nonce ?? '')}${newIdentity.public_key_der_b64}`;
      const signResult = await loaded.data.aid.sign(signPayload);
      if (!signResult.ok) return resultErr(codes.REKEY_FAILED, signResult.error.message);
      const response = await (this._auth as unknown as { _shortRpc: (url: string, method: string, params: JsonObject) => Promise<JsonObject> })
        ._shortRpc(gatewayUrl, 'auth.rekey', {
          aid: target,
          request_id: String(phase1.request_id ?? ''),
          nonce: String(phase1.nonce ?? ''),
          new_public_key: newIdentity.public_key_der_b64,
          signature: signResult.data.signature,
        });
      const certPem = String(response.cert ?? response.cert_pem ?? '').trim();
      if (!certPem) return resultErr(codes.REKEY_FAILED, 'server response missing certificate');
      const nextIdentity: IdentityRecord = {
        aid: target,
        private_key_pem: newIdentity.private_key_pem,
        public_key_der_b64: newIdentity.public_key_der_b64,
        curve: newIdentity.curve,
        cert: certPem,
      };
      await this._keystore.saveIdentity(target, nextIdentity);
      const refreshed = await this.load(target);
      if (!refreshed.ok) return resultErr(codes.REKEY_FAILED, 'rekeyed identity reload failed');
      return resultOk({
        rekeyed: true,
        newFingerprint: refreshed.data.aid.certFingerprint,
        new_fingerprint: refreshed.data.aid.certFingerprint,
      });
    } catch (exc) {
      return resultErr(codes.REKEY_FAILED, String(exc), exc);
    }
  }

  private async _resolveGateway(aid: string): Promise<string> {
    const target = String(aid ?? '').trim();
    if (!target) throw new ValidationError('AIDStore requires non-empty aid to resolve gateway');
    const issuerDomain = issuerFromAid(target);
    const cached = this._gatewayCache.get(issuerDomain);
    if (cached) return cached;
    const persisted = await this._loadCachedGatewayUrl(target);
    if (persisted) {
      this._gatewayCache.set(issuerDomain, persisted);
      return persisted;
    }

    const port = this._discoveryPort ? `:${this._discoveryPort}` : '';
    const candidates = [
      `https://${target}${port}/.well-known/aun-gateway`,
      `https://gateway.${issuerDomain}${port}/.well-known/aun-gateway`,
    ];
    let lastError: unknown = null;
    for (const url of candidates) {
      try {
        const discovered = await this._discovery.discover(url);
        this._gatewayCache.set(issuerDomain, discovered);
        await this._persistGatewayUrl(target, discovered);
        return discovered;
      } catch (exc) {
        lastError = exc;
      }
    }
    throw lastError instanceof Error ? lastError : new Error(String(lastError));
  }

  private async _loadCachedGatewayUrl(aid: string): Promise<string> {
    const getMetadata = (this._keystore as unknown as { getMetadata?: (aid: string, key: string) => Promise<string> }).getMetadata;
    if (typeof getMetadata !== 'function') return '';
    try {
      const raw = String(await getMetadata.call(this._keystore, aid, 'gateway_url') ?? '').trim();
      if (!raw) return '';
      if (raw.startsWith('"') && raw.endsWith('"')) {
        try {
          const parsed = JSON.parse(raw);
          if (typeof parsed === 'string') return parsed.trim();
        } catch {
          return raw;
        }
      }
      return raw;
    } catch {
      return '';
    }
  }

  private async _persistGatewayUrl(aid: string, gatewayUrl: string): Promise<void> {
    const setMetadata = (this._keystore as unknown as { setMetadata?: (aid: string, key: string, value: string) => Promise<void> }).setMetadata;
    if (typeof setMetadata !== 'function' || !gatewayUrl) return;
    try {
      await setMetadata.call(this._keystore, aid, 'gateway_url', gatewayUrl);
    } catch {
      // 缓存失败不影响主流程。
    }
  }
}
