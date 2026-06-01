/**
 * AIDStore — AID 管理器，对齐 Python SDK aid_store.py
 * 持有 keystore 配置，提供 AID 加载/注册/联网管理。
 */

import * as http from 'node:http';
import * as https from 'node:https';
import { X509Certificate, createPrivateKey, createPublicKey } from 'node:crypto';
import { join } from 'node:path';
import { homedir } from 'node:os';

import { AID } from './aid.js';
import * as codes from './error-codes.js';
import { certCommonName, certTimeError, signBytes, verifySignatureWithCert } from './cert-utils.js';
import { certFingerprint as _certFingerprint } from './cert-utils.js';
import { type Result, resultErr, resultOk } from './result.js';
import { LocalIdentityStore } from './keystore/local-identity-store.js';
import { CryptoProvider } from './crypto.js';
import { RegisterFlow } from './register-flow.js';
import { GatewayDiscovery } from './discovery.js';
import { DnsResilientNet } from './net.js';
import { AUNLogger } from './logger.js';
import { getDeviceId, normalizeInstanceId, normalizeSlotId } from './config.js';
import { IdentityConflictError, NotFoundError, ValidationError } from './errors.js';
import { AgentMdManager, type AgentMdCheckResult, type AgentMdDownloadResult } from './agent-md.js';

export interface AIDInfo {
  aid: string;
  certNotAfter: Date;
  certIssuer: string;
  certFingerprint: string;
}

export interface ResolveOpts {
  forceRefresh?: boolean;
  skipAgentMd?: boolean;
  timeout?: number;
}

export type ResolveResult = {
  aid: AID;
  agent_md?: DownloadAgentMdResult;
  source: { cert_from_cache: boolean; agent_md_fetched: boolean };
};
export type DownloadAgentMdResult = AgentMdDownloadResult;
export type CheckAgentMdResult = AgentMdCheckResult;
export type DiagnoseResult = { aid: string; status: string; local_valid: boolean; remote_registered: boolean; suggestions: string[]; local: Record<string, unknown>; remote: Record<string, unknown> };
export type RenewCertResult = { renewed: true; new_cert_not_after: Date; new_fingerprint: string };
export type RekeyResult = { rekeyed: true; new_cert_not_after: Date; new_fingerprint: string };
export type ChangeSeedResult = { changed: boolean; count: number };
export type ListResult = { identities: AIDInfo[] };

function resultError<T>(r: Result<T>): { code: string; message: string } | null {
  if (r.ok) return null;
  return (r as { ok: false; error: { code: string; message: string } }).error;
}

function agentMdFailure<T>(exc: unknown): Result<T> {
  if (exc instanceof ValidationError) {
    return resultErr(codes.INVALID_AID_FORMAT, exc.message, exc);
  }
  if (exc instanceof NotFoundError || String(exc).includes('AGENTMD_NOT_FOUND')) {
    return resultErr(codes.AGENTMD_NOT_FOUND, exc instanceof Error ? exc.message : String(exc), exc);
  }
  return resultErr(codes.NETWORK_ERROR, exc instanceof Error ? exc.message : String(exc), exc);
}

/** 发起 HTTP HEAD 请求，返回 [status, headers] */
function httpHead(url: string, verifySsl: boolean, timeoutMs = 5000): Promise<[number, Record<string, string>]> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;
    const opts: https.RequestOptions = { method: 'HEAD', timeout: timeoutMs };
    if (!verifySsl) opts.rejectUnauthorized = false;
    const req = mod.request(url, opts, (res) => {
      res.resume();
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(res.headers)) {
        if (typeof v === 'string') headers[k] = v;
        else if (Array.isArray(v)) headers[k] = v[0] ?? '';
      }
      resolve([res.statusCode ?? 0, headers]);
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error(`timeout HEAD ${url}`)); });
    req.end();
  });
}

function pkiCertUrl(gatewayUrl: string, aid: string): string {
  const parsed = new URL(gatewayUrl);
  const scheme = parsed.protocol === 'wss:' ? 'https:' : 'http:';
  return `${scheme}//${parsed.host}/pki/cert/${encodeURIComponent(aid)}`;
}

export class AIDStore {
  readonly aunPath: string;
  private _encryptionSeed: string;
  readonly deviceId: string;
  readonly slotId: string;

  private _keystore: LocalIdentityStore;
  private _registerFlow: RegisterFlow;
  private _discovery: GatewayDiscovery;
  private _net: DnsResilientNet;
  private _log: AUNLogger;
  private _verifySsl: boolean;
  private _rootCaPath: string | null;
  private _debug: boolean;
  private _gatewayCache: Map<string, string> = new Map();
  private _agentMdManager: AgentMdManager;

  constructor(opts: {
    aunPath: string;
    encryptionSeed: string;
    deviceId?: string;
    slotId?: string;
    verifySsl?: boolean;
    rootCaPath?: string | null;
    debug?: boolean;
  }) {
    this.aunPath = String(opts.aunPath ?? join(homedir(), '.aun'));
    this._encryptionSeed = String(opts.encryptionSeed ?? '');
    this.deviceId = opts.deviceId ? normalizeInstanceId(opts.deviceId, 'deviceId', { allowEmpty: true }) : getDeviceId(this.aunPath);
    this.slotId = normalizeSlotId(opts.slotId);
    this._verifySsl = opts.verifySsl ?? false;
    this._rootCaPath = opts.rootCaPath ?? null;
    this._debug = opts.debug ?? false;

    this._log = new AUNLogger({ debug: this._debug, aunPath: this.aunPath });
    this._log.bindDeviceId(this.deviceId);

    this._keystore = new LocalIdentityStore(this.aunPath, {
      encryptionSeed: this._encryptionSeed || undefined,
      logger: this._log.for('aun_core.keystore'),
    });

    this._net = new DnsResilientNet({ verifySsl: this._verifySsl, logger: this._log.for('aun_core.net') });
    this._discovery = new GatewayDiscovery({ verifySsl: this._verifySsl, logger: this._log.for('aun_core.discovery'), net: this._net });

    this._registerFlow = new RegisterFlow({
      keystore: this._keystore,
      crypto: new CryptoProvider(),
      verifySsl: this._verifySsl,
      logger: this._log.for('aun_core.register'),
      net: this._net,
    });

    this._agentMdManager = new AgentMdManager({
      aunPath: this.aunPath,
      verifySsl: this._verifySsl,
      logger: this._log.for('aun_core.agent_md'),
      aidValidator: (target) => this._registerFlow.validateAidName(target),
      gatewayResolver: (target) => this._resolveGateway(target),
      peerResolver: async (target) => {
        const loaded = this.load(target);
        if (loaded.ok && loaded.data) return loaded.data.aid;
        const resolved = await this.resolve(target, { skipAgentMd: true });
        if (!resolved.ok || !resolved.data) {
          const err = resultError(resolved);
          throw new Error(err?.message ?? `certificate not found for aid: ${target}`);
        }
        return resolved.data.aid;
      },
    });
  }

  close(): void {
    this._keystore.close();
    const net = this._net as unknown as { close?: () => void };
    if (typeof net.close === 'function') net.close();
  }

  // ── 离线方法 ──────────────────────────────────────────────────

  load(aid: string): Result<{ aid: AID }> {
    const target = String(aid ?? '').trim();
    const certPem = this._keystore.loadCert(target);
    if (!certPem) {
      return resultErr(codes.CERT_NOT_FOUND, `certificate not found for aid: ${target}`);
    }
    let cert: X509Certificate;
    try {
      cert = new X509Certificate(certPem);
    } catch (exc) {
      return resultErr(codes.CERT_PARSE_ERROR, `certificate parse failed for aid: ${target}`, exc);
    }

    const timeErr = certTimeError(certPem);
    if (timeErr === 'expired') return resultErr(codes.CERT_EXPIRED, `certificate expired for aid: ${target}`);
    if (timeErr === 'not_yet_valid') return resultErr(codes.CERT_NOT_YET_VALID, `certificate not yet valid for aid: ${target}`);

    const cn = certCommonName(certPem);
    if (cn && cn !== target) {
      return resultErr(codes.CERT_CHAIN_BROKEN, `certificate CN mismatch: expected ${target}, got ${cn}`);
    }

    let kp: ReturnType<LocalIdentityStore['loadKeyPair']>;
    try {
      kp = this._keystore.loadKeyPair(target);
    } catch (exc) {
      return resultErr(codes.PRIVATE_KEY_PARSE_ERROR, `private key load failed for aid: ${target}`, exc);
    }
    if (!kp || !kp.private_key_pem) {
      return resultOk({
        aid: AID._create({ aid: target, aunPath: this.aunPath, certPem, privateKeyPem: null, certValid: true, privateKeyValid: false, deviceId: this.deviceId, slotId: this.slotId, verifySsl: this._verifySsl, rootCaPath: this._rootCaPath, debug: this._debug }),
      });
    }

    const privPem = String(kp.private_key_pem);
    let privKey: ReturnType<typeof createPrivateKey>;
    try {
      privKey = createPrivateKey(privPem);
    } catch (exc) {
      return resultErr(codes.PRIVATE_KEY_PARSE_ERROR, `private key parse failed for aid: ${target}`, exc);
    }

    // 配对自检（对齐 Python aid_store.py:145-150）：
    // 1) 从私钥导出公钥 DER，与证书公钥 DER 直接比对（不依赖 key.json 的 public_key_der_b64 字段，
    //    防止该字段缺失时错配私钥蒙混过关）
    // 2) DER 比对通过后，再做 sign/verify 探针：私钥签名固定 payload，证书公钥验签
    try {
      const certPubDer = cert.publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
      const privPubDer = createPublicKey(privKey).export({ type: 'spki', format: 'der' }) as Buffer;
      if (!privPubDer.equals(certPubDer)) {
        return resultErr(codes.KEYPAIR_MISMATCH, `private key does not match certificate for aid: ${target}`);
      }
      const probe = Buffer.from('aun-aidstore-private-key-self-test', 'utf-8');
      const signature = signBytes(privPem, probe);
      if (!verifySignatureWithCert(certPem, signature, probe)) {
        return resultErr(codes.KEYPAIR_MISMATCH, `keypair self-test failed for aid: ${target}`);
      }
    } catch (exc) {
      return resultErr(codes.KEYPAIR_MISMATCH, `keypair self-test failed for aid: ${target}`, exc);
    }

    return resultOk({
      aid: AID._create({ aid: target, aunPath: this.aunPath, certPem, privateKeyPem: privPem, certValid: true, privateKeyValid: true, deviceId: this.deviceId, slotId: this.slotId, verifySsl: this._verifySsl, rootCaPath: this._rootCaPath, debug: this._debug }),
    });
  }

  list(): Result<ListResult> {
    try {
      const aids = this._keystore.listIdentities?.() ?? [];
      const identities: AIDInfo[] = [];
      for (const aid of [...aids].sort()) {
        const loaded = this.load(aid);
        if (!loaded.ok || !loaded.data) continue;
        const item = loaded.data.aid;
        if (!item.isPrivateKeyValid()) continue;
        identities.push({
          aid: item.aid,
          certNotAfter: item.certNotAfter,
          certIssuer: item.certIssuer,
          certFingerprint: item.certFingerprint,
        });
      }
      return resultOk({ identities });
    } catch (exc) {
      return resultErr('LIST_IDENTITIES_FAILED', String(exc), exc);
    }
  }

  changeSeed(oldSeed: string, newSeed: string): Result<ChangeSeedResult> {
    if (!oldSeed.trim()) return resultErr(codes.PRIVATE_KEY_PARSE_ERROR, 'changeSeed requires a non-empty oldSeed');
    if (!newSeed.trim()) return resultErr(codes.PRIVATE_KEY_PARSE_ERROR, 'changeSeed requires a non-empty newSeed');
    if (oldSeed === newSeed) return resultErr(codes.PRIVATE_KEY_PARSE_ERROR, 'newSeed must differ from oldSeed');
    try {
      const result = this._keystore.changeSeed(oldSeed, newSeed);
      this._encryptionSeed = newSeed;
      return resultOk({ changed: true, count: result.migrated ?? 0 });
    } catch (exc) {
      return resultErr(codes.PRIVATE_KEY_PARSE_ERROR, String(exc), exc);
    }
  }

  // ── 联网方法 ──────────────────────────────────────────────────

  async register(aid: string): Promise<Result<{ registered: true }>> {
    const target = String(aid ?? '').trim();
    this._log.for('aun_core.aid_store').debug(`register enter: aid=${target || '-'}`);
    try {
      this._registerFlow.validateAidName(target);
      const gatewayUrl = await this._resolveGateway(target);
      const result = await this._registerFlow.registerAid(gatewayUrl, target);
      if (result.cert) {
        this._keystore.saveCert(target, result.cert);
      }
      this._keystore.saveKeyPair(target, {
        private_key_pem: result.private_key_pem,
        public_key_der_b64: result.public_key_der_b64,
        curve: result.curve,
      });
      return resultOk({ registered: true as const });
    } catch (exc) {
      if (exc instanceof IdentityConflictError) {
        return resultErr(codes.IDENTITY_CONFLICT, String(exc), exc);
      }
      if (exc instanceof ValidationError) {
        return resultErr(codes.INVALID_AID_FORMAT, String(exc), exc);
      }
      const msg = exc instanceof Error ? exc.message : String(exc);
      if (msg.includes('network') || msg.includes('connect') || msg.includes('timeout')) {
        return resultErr(codes.NETWORK_ERROR, msg, exc);
      }
      return resultErr(codes.SERVER_ERROR, msg, exc);
    }
  }

  async exists(aid: string): Promise<Result<{ exists: boolean }>> {
    const target = String(aid ?? '').trim();
    try {
      this._registerFlow.validateAidName(target);
      const gatewayUrl = await this._resolveGateway(target);
      const url = pkiCertUrl(gatewayUrl, target);
      const [status] = await httpHead(url, this._verifySsl, 5000);
      if (status === 200) return resultOk({ exists: true });
      if (status === 404) return resultOk({ exists: false });
      return resultErr(codes.NETWORK_ERROR, `unexpected PKI HEAD status ${status}`);
    } catch (exc) {
      return resultErr(codes.NETWORK_ERROR, String(exc), exc);
    }
  }

  async resolve(aid: string, opts?: ResolveOpts): Promise<Result<ResolveResult>> {
    const target = String(aid ?? '').trim();
    const forceRefresh = !!(opts?.forceRefresh);
    const skipAgentMd = !!(opts?.skipAgentMd);
    try {
      this._registerFlow.validateAidName(target);
      let peer: AID;
      let certFromCache = false;
      const loaded = this.load(target);
      if (loaded.ok && loaded.data && !forceRefresh) {
        peer = loaded.data.aid;
        certFromCache = true;
      } else {
        const gatewayUrl = await this._resolveGateway(target);
        const certPem = await this._registerFlow.fetchPeerCert(gatewayUrl, target);
        if (!certPem) return resultErr(codes.CERT_NOT_FOUND, `certificate not found for aid: ${target}`);
        this._keystore.saveCert(target, certPem);
        const reloaded = this.load(target);
        if (!reloaded.ok || !reloaded.data) return reloaded as Result<never>;
        peer = reloaded.data.aid;
      }
      const source = { cert_from_cache: certFromCache, agent_md_fetched: false };
      if (skipAgentMd) return resultOk({ aid: peer, source });
      const agentMd = await this.downloadAgentMd(target, opts?.timeout ?? 10000);
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

  async diagnose(aid: string): Promise<Result<DiagnoseResult>> {
    const target = String(aid ?? '').trim();
    const loaded = this.load(target);
    const existsResult = await this.exists(target);
    const remoteError = resultError(existsResult);
    const remoteRegistered = !!(existsResult.ok && existsResult.data?.exists);
    const remoteChecked = !!(existsResult.ok && existsResult.data != null);

    let localCert = false;
    let localPrivateKey = false;
    let localError: unknown = null;
    let localAid: AID | null = null;
    if (loaded.ok && loaded.data) {
      localAid = loaded.data.aid;
      localCert = localAid.isCertValid();
      localPrivateKey = localAid.isPrivateKeyValid();
    } else {
      localError = resultError(loaded);
    }

    const localValid = localCert && localPrivateKey;
    const suggestions: string[] = [];
    if (!localValid) suggestions.push('load or register a local identity with a valid private key');
    if (!remoteRegistered) suggestions.push('register the AID before using it on the network');
    if (remoteError) suggestions.push(`remote registration check failed: ${remoteError.message}`);

    let status: string;
    if (localPrivateKey && remoteRegistered) status = 'ready';
    else if (!localPrivateKey && remoteChecked && !remoteRegistered) status = 'available';
    else if (remoteRegistered) status = 'registered_remote';
    else status = 'unknown';

    return resultOk({
      aid: target, status, local_valid: localValid,
      remote_registered: remoteRegistered,
      suggestions,
      local: { cert: localCert, private_key: localPrivateKey, error: localError },
      remote: { checked: remoteChecked, exists: remoteChecked ? remoteRegistered : null, error: remoteError },
    });
  }

  async renewCert(aid: string): Promise<Result<RenewCertResult>> {
    const target = String(aid ?? '').trim();
    const loaded = this.load(target);
    if (!loaded.ok || !loaded.data || !loaded.data.aid.isPrivateKeyValid()) {
      return resultErr(codes.PRIVATE_KEY_REQUIRED, `private key required for aid: ${target}`);
    }
    try {
      this._registerFlow.validateAidName(target);
      const gatewayUrl = await this._resolveGateway(target);
      const aidObj = loaded.data.aid;
      const clientNonce = this._registerFlow.newClientNonce();
      const phase1 = await this._registerFlow.shortRpc(gatewayUrl, 'auth.aid_login1', {
        aid: target, cert: aidObj.certPem, client_nonce: clientNonce,
      });
      await this._registerFlow.verifyPhase1Response(gatewayUrl, phase1, clientNonce);
      const signResult = aidObj.sign(String(phase1.nonce));
      if (!signResult.ok || !signResult.data) {
        return resultErr(codes.CERT_RENEWAL_FAILED, resultError(signResult)?.message ?? 'sign failed');
      }
      const response = await this._registerFlow.shortRpc(gatewayUrl, 'auth.renew_cert', {
        aid: target, request_id: String(phase1.request_id), nonce: String(phase1.nonce), signature: signResult.data.signature,
      });
      const certPem = String(response.cert ?? response.cert_pem ?? '').trim();
      if (!certPem) return resultErr(codes.CERT_RENEWAL_FAILED, 'server response missing certificate');
      this._keystore.saveCert(target, certPem);
      const refreshed = this.load(target);
      if (!refreshed.ok || !refreshed.data) return resultErr(codes.CERT_RENEWAL_FAILED, 'renewed certificate reload failed');
      const refreshedAid = refreshed.data.aid;
      return resultOk({ renewed: true, new_cert_not_after: refreshedAid.certNotAfter, new_fingerprint: refreshedAid.certFingerprint });
    } catch (exc) {
      return resultErr(codes.CERT_RENEWAL_FAILED, String(exc), exc);
    }
  }

  async rekey(aid: string): Promise<Result<RekeyResult>> {
    const target = String(aid ?? '').trim();
    const loaded = this.load(target);
    if (!loaded.ok || !loaded.data || !loaded.data.aid.isPrivateKeyValid()) {
      return resultErr(codes.PRIVATE_KEY_REQUIRED, `private key required for aid: ${target}`);
    }
    try {
      this._registerFlow.validateAidName(target);
      const oldAid = loaded.data.aid;
      const newIdentity = this._registerFlow.generateIdentity();
      const gatewayUrl = await this._resolveGateway(target);
      const clientNonce = this._registerFlow.newClientNonce();
      const phase1 = await this._registerFlow.shortRpc(gatewayUrl, 'auth.aid_login1', {
        aid: target, cert: oldAid.certPem, client_nonce: clientNonce,
      });
      await this._registerFlow.verifyPhase1Response(gatewayUrl, phase1, clientNonce);
      const signPayload = Buffer.from(`${phase1.nonce}${newIdentity.public_key_der_b64}`, 'utf-8');
      const signResult = oldAid.sign(signPayload);
      if (!signResult.ok || !signResult.data) {
        return resultErr(codes.REKEY_FAILED, resultError(signResult)?.message ?? 'sign failed');
      }
      const response = await this._registerFlow.shortRpc(gatewayUrl, 'auth.rekey', {
        aid: target, request_id: String(phase1.request_id), nonce: String(phase1.nonce),
        new_public_key: newIdentity.public_key_der_b64, signature: signResult.data.signature,
      });
      const certPem = String(response.cert ?? response.cert_pem ?? '').trim();
      if (!certPem) return resultErr(codes.REKEY_FAILED, 'server response missing certificate');
      this._keystore.saveIdentity(target, { aid: target, ...newIdentity, cert: certPem });
      const refreshed = this.load(target);
      if (!refreshed.ok || !refreshed.data) return resultErr(codes.REKEY_FAILED, 'rekeyed identity reload failed');
      const refreshedAid = refreshed.data.aid;
      return resultOk({ rekeyed: true, new_fingerprint: refreshedAid.certFingerprint, new_cert_not_after: refreshedAid.certNotAfter });
    } catch (exc) {
      return resultErr(codes.REKEY_FAILED, String(exc), exc);
    }
  }

  // ── 内部辅助 ──────────────────────────────────────────────────

  private async _resolveGateway(aid: string): Promise<string> {
    const dotIdx = aid.indexOf('.');
    const issuerDomain = dotIdx >= 0 ? aid.slice(dotIdx + 1) : aid;
    const cached = this._gatewayCache.get(issuerDomain);
    if (cached) return cached;
    const gatewayUrl = `https://gateway.${issuerDomain}/.well-known/aun-gateway`;
    const discovered = await this._discovery.discover(gatewayUrl);
    this._gatewayCache.set(issuerDomain, discovered);
    return discovered;
  }
}
