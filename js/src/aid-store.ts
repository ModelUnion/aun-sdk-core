import { AID } from './aid.js';
import { CryptoProvider, pemToArrayBuffer, importPrivateKeyEcdsa, importCertPublicKeyEcdsa, ecdsaSignDer, ecdsaVerifyDer } from './crypto.js';
import * as codes from './error-codes.js';
import { publicKeyDerB64 } from './cert-utils.js';
import { RegisterFlow } from './register-flow.js';
import { GatewayDiscovery } from './discovery.js';
import { IdentityConflictError, NotFoundError, ValidationError } from './errors.js';
import { IndexedDBIdentityStore } from './keystore/indexeddb-identity-store.js';
import { IndexedDBTokenStore } from './keystore/indexeddb-token-store.js';
import { getDeviceId, normalizeSlotId } from './config.js';
import type { IdentityRecord } from './types.js';
import { resultErr, resultOk, type Result } from './result.js';
import { AgentMdManager, type AgentMdCheckResult, type AgentMdDownloadResult } from './agent-md.js';
import { AuthFlow } from './auth.js';

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

export type ResolveResult = {
  aid: AID;
  agent_md?: DownloadAgentMdResult;
  source: { cert_from_cache: boolean; agent_md_fetched: boolean };
};
export type DownloadAgentMdResult = AgentMdDownloadResult;
export type CheckAgentMdResult = AgentMdCheckResult;
export type UploadAgentMdResult = Record<string, unknown>;
export type DiagnoseResult = { aid: string; status: string; local_valid: boolean; remote_registered: boolean; suggestions: string[]; local: Record<string, unknown>; remote: Record<string, unknown> };
export type RenewCertResult = { renewed: true; new_cert_not_after: Date; new_fingerprint: string };
export type RekeyResult = { rekeyed: true; new_cert_not_after: Date; new_fingerprint: string };
export type ChangeSeedResult = { changed: boolean; count: number };
export type ListResult = { identities: AIDInfo[] };

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

function issuerFromAid(aid: string): string {
  const target = String(aid ?? '').trim();
  const dotIdx = target.indexOf('.');
  return dotIdx >= 0 ? target.slice(dotIdx + 1) : target;
}

function gatewayHttpUrl(gatewayUrl: string, path: string): string {
  const parsed = new URL(gatewayUrl);
  parsed.protocol = parsed.protocol === 'wss:' ? 'https:' : 'http:';
  parsed.pathname = path;
  parsed.search = '';
  parsed.hash = '';
  return parsed.toString();
}

function pkiCertUrl(gatewayUrl: string, aid: string, certFingerprint?: string | null): string {
  const url = new URL(gatewayHttpUrl(gatewayUrl, `/pki/cert/${encodeURIComponent(aid)}`));
  const fp = String(certFingerprint ?? '').trim().toLowerCase();
  if (fp) url.searchParams.set('cert_fingerprint', fp);
  return url.toString();
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

function agentMdFailure<T>(exc: unknown): Result<T> {
  if (exc instanceof ValidationError) {
    return resultErr(codes.INVALID_AID_FORMAT, exc.message, exc);
  }
  if (exc instanceof NotFoundError) {
    return resultErr(codes.AGENTMD_NOT_FOUND, exc.message, exc);
  }
  return resultErr(codes.NETWORK_ERROR, exc instanceof Error ? exc.message : String(exc), exc);
}

export class AIDStore {
  readonly aunPath: string;
  readonly deviceId: string;
  readonly slotId: string;

  private _encryptionSeed: string;
  private _keystore: IndexedDBIdentityStore;
  private _tokenStore: IndexedDBTokenStore;
  private _registerFlow: RegisterFlow;
  private _discovery: GatewayDiscovery;
  private _crypto: CryptoProvider;
  private _rootCaPem: string | null;
  private _verifySsl: boolean;
  private _gatewayCache: Map<string, string> = new Map();
  private _agentMdManager: AgentMdManager;

  constructor(opts: {
    aunPath: string;
    encryptionSeed: string;
    slotId?: string;
    rootCaPem?: string | null;
    verifySsl?: boolean;
  }) {
    this.aunPath = String(opts.aunPath ?? '');
    this._encryptionSeed = String(opts.encryptionSeed ?? '');
    this.deviceId = getDeviceId();
    this.slotId = normalizeSlotId(opts.slotId);
    if (opts.verifySsl === false) {
      console.warn('[aun_core.config] verify_ssl=false 在浏览器环境中不受支持，SSL 证书验证将保持启用。');
    }
    this._verifySsl = opts.verifySsl === false ? true : (opts.verifySsl ?? true);
    this._rootCaPem = opts.rootCaPem ?? null;
    this._keystore = new IndexedDBIdentityStore({ encryptionSeed: this._encryptionSeed || undefined });
    this._tokenStore = new IndexedDBTokenStore();
    this._crypto = new CryptoProvider();
    this._discovery = new GatewayDiscovery();
    this._registerFlow = new RegisterFlow({
      keystore: this._keystore,
      crypto: this._crypto,
      verifySsl: this._verifySsl,
    });
    this._agentMdManager = new AgentMdManager({
      aunPath: this.aunPath,
      tokenStore: this._tokenStore,
      aidValidator: (target) => this._registerFlow.validateAidName(target),
      gatewayResolver: (target) => this._resolveGateway(target),
      peerResolver: async (target, certFingerprint) => {
        const fp = String(certFingerprint ?? '').trim().toLowerCase();
        const cachedCert = await this._keystore.loadCert(target, fp || undefined);
        if (cachedCert) {
          return await AID.create({ aid: target, aunPath: this.aunPath, certPem: cachedCert, privateKeyPem: null, certValid: true, privateKeyValid: false });
        }
        if (fp) {
          const gatewayUrl = await this._resolveGateway(target);
          const response = await fetchWithTimeout(pkiCertUrl(gatewayUrl, target, fp), { method: 'GET' }, 10000);
          if (!response.ok) throw new Error(`certificate not found for aid: ${target}`);
          const certPem = await response.text();
          await this._keystore.saveCert(target, certPem, fp, { makeActive: false });
          return await AID.create({ aid: target, aunPath: this.aunPath, certPem, privateKeyPem: null, certValid: true, privateKeyValid: false });
        }
        const gatewayUrl = await this._resolveGateway(target);
        const certPem = await this._registerFlow.fetchPeerCert(gatewayUrl, target);
        if (!certPem) throw new Error(`certificate not found for aid: ${target}`);
        await this._keystore.saveCert(target, certPem);
        return await AID.create({ aid: target, aunPath: this.aunPath, certPem, privateKeyPem: null, certValid: true, privateKeyValid: false });
      },
    });
  }

  close(): void {
    const close = (this._keystore as unknown as { close?: () => void }).close;
    if (typeof close === 'function') close.call(this._keystore);
    const closeTokens = (this._tokenStore as unknown as { close?: () => void }).close;
    if (typeof closeTokens === 'function') closeTokens.call(this._tokenStore);
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
          verifySsl: this._verifySsl,
          rootCaPath: null,
          debug: false,
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
        verifySsl: this._verifySsl,
        rootCaPath: null,
        debug: false,
      }),
    });
  }

  async list(): Promise<Result<ListResult>> {
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

  async changeSeed(oldSeed: string, newSeed: string): Promise<Result<ChangeSeedResult>> {
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
      if (!target) throw new ValidationError("AIDStore.register requires 'aid'");
      this._registerFlow.validateAidName(target);
      const gatewayUrl = await this._resolveGateway(target);
      const result = await this._registerFlow.registerAid(gatewayUrl, target);
      if (result.cert) {
        await this._keystore.saveCert(target, result.cert);
      }
      if (result.private_key_pem || result.public_key_der_b64) {
        await this._keystore.saveKeyPair(target, {
          private_key_pem: result.private_key_pem,
          public_key_der_b64: result.public_key_der_b64,
          curve: result.curve,
        });
      }
      await this._persistGatewayUrl(target, gatewayUrl);
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
      this._registerFlow.validateAidName(target);
      const gatewayUrl = await this._resolveGateway(target);
      const response = await fetchWithTimeout(pkiCertUrl(gatewayUrl, target), { method: 'HEAD' }, 10000);
      if (response.status === 200) return resultOk({ exists: true });
      if (response.status === 404) return resultOk({ exists: false });
      return resultErr(codes.NETWORK_ERROR, `unexpected PKI HEAD status ${response.status}`);
    } catch (exc) {
      return resultErr(codes.NETWORK_ERROR, String(exc), exc);
    }
  }

  async resolve(aid: string, opts?: ResolveOpts): Promise<Result<ResolveResult>> {
    const target = String(aid ?? '').trim();
    const forceRefresh = !!opts?.forceRefresh;
    const skipAgentMd = !!opts?.skipAgentMd;
    try {
      this._registerFlow.validateAidName(target);
      let peer: AID;
      let certFromCache = false;
      const cached = await this.load(target);
      if (cached.ok && !forceRefresh) {
        peer = cached.data.aid;
        certFromCache = true;
      } else {
        const gatewayUrl = await this._resolveGateway(target);
        const certPem = await this._registerFlow.fetchPeerCert(gatewayUrl, target);
        if (!certPem) return resultErr(codes.CERT_NOT_FOUND, `certificate not found for aid: ${target}`);
        await this._keystore.saveCert(target, certPem);
        await this._persistGatewayUrl(target, gatewayUrl);
        const reloaded = await this.load(target);
        if (!reloaded.ok) return reloaded as Result<never>;
        peer = reloaded.data.aid;
      }

      const source = { cert_from_cache: certFromCache, agent_md_fetched: false };
      if (skipAgentMd) return resultOk({ aid: peer, source });

      const agentMd = await this.downloadAgentMd(target, opts?.timeout);
      if (!agentMd.ok) return agentMd as Result<never>;
      source.agent_md_fetched = true;
      return resultOk({ aid: peer, agent_md: agentMd.data, source });
    } catch (exc) {
      return resultErr(codes.NETWORK_ERROR, String(exc), exc);
    }
  }

  async downloadAgentMd(aid: string, timeoutMs = 30000): Promise<Result<DownloadAgentMdResult>> {
    try {
      return resultOk(await this._agentMdManager.download(aid, timeoutMs));
    } catch (exc) {
      return agentMdFailure<DownloadAgentMdResult>(exc);
    }
  }

  async checkAgentMd(aid: string, ttlDays = 1): Promise<Result<CheckAgentMdResult>> {
    try {
      return resultOk(await this._agentMdManager.check(aid, ttlDays));
    } catch (exc) {
      return agentMdFailure<CheckAgentMdResult>(exc);
    }
  }

  private _authIdentityFromAid(aid: AID): IdentityRecord {
    return {
      aid: aid.aid,
      private_key_pem: aid.privateKeyPem,
      public_key_der_b64: aid.publicKey,
      cert: aid.certPem,
    };
  }

  private async _uploadAgentMdToken(aid: AID, gatewayUrl: string): Promise<string> {
    const auth = new AuthFlow({
      tokenStore: this._tokenStore,
      crypto: this._crypto,
      aid: aid.aid,
      deviceId: this.deviceId,
      slotId: this.slotId,
      rootCaPem: this._rootCaPem,
      verifySsl: this._verifySsl,
    });
    auth.setIdentity(this._authIdentityFromAid(aid));
    const result = await auth.authenticate(gatewayUrl, aid.aid);
    const token = String(result.access_token ?? result.token ?? result.kite_token ?? '').trim();
    if (!token) throw new Error('authenticate did not return access_token');
    return token;
  }

  async uploadAgentMd(aid: string, content?: string | null): Promise<Result<UploadAgentMdResult>> {
    const target = String(aid ?? '').trim();
    try {
      this._registerFlow.validateAidName(target);
      const loaded = await this.load(target);
      if (!loaded.ok) {
        return resultErr(loaded.error.code, loaded.error.message);
      }
      const current = loaded.data.aid;
      if (!current.isPrivateKeyValid() || !current.privateKeyPem) {
        return resultErr(codes.PRIVATE_KEY_NOT_VALID, `uploadAgentMd requires local AID with a valid private key: ${target}`);
      }
      const manager = new AgentMdManager({
        aunPath: this.aunPath,
        tokenStore: this._tokenStore,
        ownerAidGetter: () => target,
        currentAidGetter: () => current,
        gatewayResolver: (value) => this._resolveGateway(value),
        accessTokenResolver: (_value, gatewayUrl) => this._uploadAgentMdToken(current, gatewayUrl),
        aidValidator: (value) => this._registerFlow.validateAidName(value),
      });
      return resultOk(await manager.upload(content));
    } catch (exc) {
      return agentMdFailure<UploadAgentMdResult>(exc);
    }
  }

  async diagnose(aid: string): Promise<Result<DiagnoseResult>> {
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

  async renewCert(aid: string): Promise<Result<RenewCertResult>> {
    const target = String(aid ?? '').trim();
    const loaded = await this.load(target);
    if (!loaded.ok || !loaded.data.aid.isPrivateKeyValid()) {
      return resultErr(codes.PRIVATE_KEY_REQUIRED, `private key required for aid: ${target}`);
    }
    try {
      this._registerFlow.validateAidName(target);
      const aidObj = loaded.data.aid;
      if (!aidObj.certPem || !aidObj.privateKeyPem) {
        return resultErr(codes.PRIVATE_KEY_REQUIRED, `private key required for aid: ${target}`);
      }
      const gatewayUrl = await this._resolveGateway(target);
      const phase1 = await this._beginAidOperation(gatewayUrl, aidObj);
      const signResult = await aidObj.sign(String(phase1.nonce));
      if (!signResult.ok || !signResult.data) {
        return resultErr(codes.CERT_RENEWAL_FAILED, resultError(signResult)?.message ?? 'sign failed');
      }
      const response = await this._registerFlow.shortRpc(gatewayUrl, 'auth.renew_cert', {
          aid: target,
          request_id: String(phase1.request_id ?? ''),
          nonce: String(phase1.nonce ?? ''),
          signature: signResult.data.signature,
        });
      const certPem = String(response.cert ?? response.cert_pem ?? '').trim();
      if (!certPem) return resultErr(codes.CERT_RENEWAL_FAILED, 'server response missing certificate');
      await this._keystore.saveCert(target, certPem);
      const refreshed = await this.load(target);
      if (!refreshed.ok) return resultErr(codes.CERT_RENEWAL_FAILED, 'renewed certificate reload failed');
      return resultOk({
        renewed: true as const,
        new_cert_not_after: refreshed.data.aid.certNotAfter,
        new_fingerprint: refreshed.data.aid.certFingerprint,
      });
    } catch (exc) {
      return resultErr(codes.CERT_RENEWAL_FAILED, String(exc), exc);
    }
  }

  async rekey(aid: string): Promise<Result<RekeyResult>> {
    const target = String(aid ?? '').trim();
    const loaded = await this.load(target);
    if (!loaded.ok || !loaded.data.aid.isPrivateKeyValid()) {
      return resultErr(codes.PRIVATE_KEY_REQUIRED, `private key required for aid: ${target}`);
    }
    try {
      this._registerFlow.validateAidName(target);
      const oldAid = loaded.data.aid;
      if (!oldAid.certPem || !oldAid.privateKeyPem) {
        return resultErr(codes.PRIVATE_KEY_REQUIRED, `private key required for aid: ${target}`);
      }
      const gatewayUrl = await this._resolveGateway(target);
      const newIdentity = await this._registerFlow.generateIdentity();
      const phase1 = await this._beginAidOperation(gatewayUrl, oldAid);
      const signPayload = `${String(phase1.nonce ?? '')}${newIdentity.public_key_der_b64}`;
      const signResult = await loaded.data.aid.sign(signPayload);
      if (!signResult.ok) return resultErr(codes.REKEY_FAILED, signResult.error.message);
      const response = await this._registerFlow.shortRpc(gatewayUrl, 'auth.rekey', {
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
        rekeyed: true as const,
        new_cert_not_after: refreshed.data.aid.certNotAfter,
        new_fingerprint: refreshed.data.aid.certFingerprint,
      });
    } catch (exc) {
      return resultErr(codes.REKEY_FAILED, String(exc), exc);
    }
  }

  private async _beginAidOperation(gatewayUrl: string, aidObj: AID): Promise<{ request_id: string; nonce: string }> {
    const clientNonce = this._registerFlow.newClientNonce();
    const phase1 = await this._registerFlow.shortRpc(gatewayUrl, 'auth.aid_login1', {
      aid: aidObj.aid,
      cert: aidObj.certPem,
      client_nonce: clientNonce,
    });
    await this._registerFlow.verifyPhase1Response(gatewayUrl, phase1, clientNonce);
    const requestId = String(phase1.request_id ?? '').trim();
    const nonce = String(phase1.nonce ?? '').trim();
    if (!requestId) throw new ValidationError('aid_login1 response missing request_id');
    if (!nonce) throw new ValidationError('aid_login1 response missing nonce');
    return { request_id: requestId, nonce };
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

    const port = '';
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
      if (!await this._hasLocalAidMaterial(aid)) return;
      await setMetadata.call(this._keystore, aid, 'gateway_url', gatewayUrl);
    } catch {
      // 缓存失败不影响主流程。
    }
  }

  private async _hasLocalAidMaterial(aid: string): Promise<boolean> {
    try {
      const cert = await this._keystore.loadCert(aid);
      if (cert) return true;
      return !!await this._keystore.loadKeyPair(aid);
    } catch {
      return false;
    }
  }
}
