/**
 * RegisterFlow — AID 注册流程（独立类，不继承 AuthFlow）
 * 与 Python SDK register_aid 对齐。
 */

import * as crypto from 'node:crypto';
import * as http from 'node:http';
import * as https from 'node:https';

import WebSocket from 'ws';

import { AuthFlow } from './auth.js';
import type { FullKeyStore } from './keystore/index.js';
import { AuthError, IdentityConflictError, ValidationError, mapRemoteError } from './errors.js';
import { isJsonObject, type IdentityRecord, type KeyPairRecord, type JsonObject, type RpcParams } from './types.js';
import type { CryptoProvider } from './crypto.js';
import type { ModuleLogger } from './logger.js';
import type { DnsResilientNet } from './net.js';

const _noopLogger: ModuleLogger = { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} };

type PendingKeyStore = FullKeyStore & {
  pendingIdentityDir(aid: string): string;
  listPendingIdentityDirs(aid: string): string[];
  savePendingKeyPair(handle: string, aid: string, keyPair: KeyPairRecord): void;
  loadPendingKeyPair(handle: string, aid: string): KeyPairRecord | null;
  savePendingCert(handle: string, certPem: string): void;
  promotePendingIdentity(handle: string, aid: string): string;
  discardPendingIdentity?(handle: string): void;
};

function _loadX509(pem: string): crypto.X509Certificate {
  return new crypto.X509Certificate(pem);
}

function _extractPublicKey(cert: crypto.X509Certificate): crypto.KeyObject {
  const pk = cert.publicKey;
  if (pk && typeof pk === 'object' && 'type' in pk) return pk as crypto.KeyObject;
  return crypto.createPublicKey(cert.toString());
}

function _gatewayHttpUrl(gatewayUrl: string, urlPath: string): string {
  const parsed = new URL(gatewayUrl);
  const scheme = parsed.protocol === 'wss:' ? 'https:' : 'http:';
  return `${scheme}//${parsed.host}${urlPath}`;
}

function _httpGet(url: string, verifySsl: boolean): Promise<string> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;
    const opts: https.RequestOptions = { timeout: 5000 };
    if (!verifySsl) opts.rejectUnauthorized = false;
    const req = mod.get(url, opts, (res) => {
      if (res.statusCode && (res.statusCode < 200 || res.statusCode >= 300)) {
        reject(new Error(`HTTP ${res.statusCode} from ${url}`));
        res.resume();
        return;
      }
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error(`timeout GET ${url}`)); });
  });
}

function _defaultConnectionFactory(url: string): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url, { handshakeTimeout: 5000, rejectUnauthorized: false });
    ws.on('open', () => resolve(ws));
    ws.on('error', (err) => reject(new AuthError(`websocket connect failed: ${err.message}`)));
  });
}

export interface RegisterResult {
  aid: string;
  cert: string;
  private_key_pem: string;
  public_key_der_b64: string;
  curve: string;
}

export class RegisterFlow {
  private _keystore: PendingKeyStore;
  private _crypto: CryptoProvider;
  private _verifySsl: boolean;
  private _logger: ModuleLogger;
  private _net: DnsResilientNet | null;

  constructor(opts: {
    keystore: PendingKeyStore;
    crypto: CryptoProvider;
    verifySsl?: boolean;
    logger?: ModuleLogger;
    net?: DnsResilientNet | null;
  }) {
    this._keystore = opts.keystore;
    this._crypto = opts.crypto;
    this._verifySsl = opts.verifySsl ?? false;
    this._logger = opts.logger ?? _noopLogger;
    this._net = opts.net ?? null;
  }

  async registerAid(gatewayUrl: string, aid: string): Promise<RegisterResult> {
    const tStart = Date.now();
    AuthFlow._validateAidName(aid);
    this._logger.debug(`registerAid enter: aid=${aid}, gateway=${gatewayUrl}`);
    try {
      const pendingStore = this._pendingStore();
      // Step 1: 本地完整身份的幂等处理
      const existing = this._keystore.loadIdentity(aid);
      if (existing !== null && existing.public_key_der_b64) {
        this._logger.debug(`registerAid: local keypair exists, checking server for idempotency: aid=${aid}`);
        const localPubB64 = String(existing.public_key_der_b64);
        const serverCertPem = await this._downloadRegisteredCert(gatewayUrl, aid);
        if (!serverCertPem) {
          // 服务端无记录 → 用现有 keypair 发起注册
          this._logger.debug(`registerAid: server has no record, registering with existing keypair: aid=${aid}`);
          let created: JsonObject;
          try {
            created = await this._createAid(gatewayUrl, existing as IdentityRecord);
          } catch (e) {
            this._logger.warn(`registerAid RPC failed (existing keypair): aid=${aid}, error=${e instanceof Error ? e.message : String(e)}`);
            throw e;
          }
          const certPem = String(created.cert ?? '');
          if (!certPem) throw new AuthError(`registerAid: server response missing cert for ${aid}`);
          existing.cert = certPem;
          this._assertCertMatchesLocalKeypair(existing);
          this._persistIdentity(existing);
          this._logger.debug(`registerAid exit (recovered): elapsed=${Date.now() - tStart}ms aid=${aid}`);
          return {
            aid,
            cert: certPem,
            private_key_pem: String(existing.private_key_pem ?? ''),
            public_key_der_b64: localPubB64,
            curve: String(existing.curve ?? 'P-256'),
          };
        }
        // 比对公钥
        const cert = _loadX509(serverCertPem);
        const serverPubDer = _extractPublicKey(cert).export({ type: 'spki', format: 'der' });
        const localPubDer = Buffer.from(localPubB64, 'base64');
        if (!(serverPubDer as Buffer).equals(localPubDer)) {
          throw new IdentityConflictError(
            `AID '${aid}' is registered by another party on server (public key mismatch). Choose a different name.`,
          );
        }
        // 公钥匹配 → 幂等返回
        this._logger.info(`registerAid: idempotent return for already-registered AID: aid=${aid}`);
        if (!existing.cert) {
          existing.cert = serverCertPem;
          this._persistIdentity(existing);
        }
        return {
          aid,
          cert: serverCertPem,
          private_key_pem: String(existing.private_key_pem ?? ''),
          public_key_der_b64: localPubB64,
          curve: String(existing.curve ?? 'P-256'),
        };
      }

      // Step 2: 检查 _pending/ 残留临时目录（崩溃恢复）
      const recovered = await this._tryRecoverPendingRegistration(gatewayUrl, aid);
      if (recovered !== null) {
        this._logger.info(`registerAid recovered from pending: aid=${aid}`);
        return recovered;
      }

      // Step 3: 服务端查重
      const existingCert = await this._downloadRegisteredCert(gatewayUrl, aid);
      if (existingCert) {
        this._logger.warn(`registerAid aborted: AID already registered on server: aid=${aid}`);
        throw new IdentityConflictError(
          `AID '${aid}' is already registered on server. Choose a different name, or if you own the keypair use a recovery flow.`,
        );
      }

      // Step 4: 创建临时目录 + 生成 keypair + 写 priv
      const identity = this._crypto.generateIdentity() as IdentityRecord;
      identity.aid = aid;
      const pendingDir = await pendingStore.pendingIdentityDir(aid);
      await pendingStore.savePendingKeyPair(pendingDir, aid, identity);

      // Step 5: 服务端注册拿 cert
      let created: JsonObject;
      try {
        created = await this._createAid(gatewayUrl, identity);
      } catch (e) {
        this._logger.warn(`registerAid RPC failed (pending kept for recovery): aid=${aid}, pending=${pendingDir}, error=${e instanceof Error ? e.message : String(e)}`);
        throw e;
      }
      const certPem = String(created.cert ?? '');
      if (!certPem) throw new AuthError(`registerAid: server response missing cert for ${aid}`);
      identity.cert = certPem;

      // Step 6: 校验 cert 公钥 == 本地公钥
      this._assertCertMatchesLocalKeypair(identity);

      // Step 7: 写 cert.pem 到临时目录
      await pendingStore.savePendingCert(pendingDir, certPem);

      // Step 8: 原子 rename
      try {
        await pendingStore.promotePendingIdentity(pendingDir, aid);
      } catch (e) {
        this._logger.warn(`registerAid promote failed: aid=${aid}, error=${e instanceof Error ? e.message : String(e)}`);
        throw new IdentityConflictError(
          `AID '${aid}' was created by another process during registration; pending dir kept for cleanup.`,
        );
      }

      // Step 9: 持久化（仅 cert，私钥由调用方写入）
      this._persistIdentity(identity);
      this._logger.debug(`registerAid exit: elapsed=${Date.now() - tStart}ms aid=${aid}`);
      return {
        aid: String(identity.aid),
        cert: certPem,
        private_key_pem: String(identity.private_key_pem ?? ''),
        public_key_der_b64: String(identity.public_key_der_b64 ?? ''),
        curve: String(identity.curve ?? 'P-256'),
      };
    } catch (err) {
      this._logger.debug(`registerAid exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  private async _tryRecoverPendingRegistration(gatewayUrl: string, aid: string): Promise<RegisterResult | null> {
    const pendingStore = this._pendingStore();
    const candidates = await pendingStore.listPendingIdentityDirs(aid);
    if (candidates.length === 0) return null;

    for (const pendingDir of candidates) {
      let privData: KeyPairRecord | null;
      try {
        privData = await pendingStore.loadPendingKeyPair(pendingDir, aid);
      } catch (exc) {
        this._logger.warn(`pending identity keypair load failed; keeping pending for retry: aid=${aid}, pending=${pendingDir}, error=${exc instanceof Error ? exc.message : String(exc)}`);
        throw exc;
      }
      const localPriv = String(privData?.private_key_pem ?? '');
      const localPubB64 = String(privData?.public_key_der_b64 ?? '');
      if (!localPriv || !localPubB64) {
        await pendingStore.discardPendingIdentity?.(pendingDir);
        continue;
      }

      const serverCert = await this._downloadRegisteredCert(gatewayUrl, aid);
      if (!serverCert) {
        this._logger.info(`pending dir found but server has no registration; cleaning up: ${pendingDir}`);
        await pendingStore.discardPendingIdentity?.(pendingDir);
        return null;
      }

      const cert = _loadX509(serverCert);
      const certPubDer = _extractPublicKey(cert).export({ type: 'spki', format: 'der' });
      const localPubDer = Buffer.from(localPubB64, 'base64');
      if (!(certPubDer as Buffer).equals(localPubDer)) {
        this._logger.warn(`pending dir public key does not match server cert; AID '${aid}' was taken`);
        await pendingStore.discardPendingIdentity?.(pendingDir);
        throw new IdentityConflictError(
          `AID '${aid}' has been registered by another party while local pending registration was incomplete; local pending key discarded.`,
        );
      }

      this._logger.info(`pending recovery: cert public key matches; finalizing registration: aid=${aid}`);
      pendingStore.savePendingCert(pendingDir, serverCert);
      const identity: IdentityRecord = {
        aid,
        private_key_pem: localPriv,
        public_key_der_b64: localPubB64,
        curve: String(privData?.curve ?? 'P-256'),
        cert: serverCert,
      };
      await pendingStore.savePendingKeyPair(pendingDir, aid, identity);
      try {
        await pendingStore.promotePendingIdentity(pendingDir, aid);
      } catch (e) {
        throw new IdentityConflictError(
          `AID '${aid}' was created by another process during recovery; pending dir kept for cleanup.`,
        );
      }
      this._persistIdentity(identity);
      return { aid, cert: serverCert, private_key_pem: localPriv, public_key_der_b64: localPubB64, curve: String(privData?.curve ?? 'P-256') };
    }
    return null;
  }

  private _pendingStore(): PendingKeyStore {
    const store = this._keystore as Partial<PendingKeyStore>;
    for (const name of [
      'pendingIdentityDir',
      'listPendingIdentityDirs',
      'savePendingKeyPair',
      'loadPendingKeyPair',
      'savePendingCert',
      'promotePendingIdentity',
    ] as const) {
      if (typeof store[name] !== 'function') {
        throw new AuthError(`keystore does not support pending registration: ${name}`);
      }
    }
    return this._keystore;
  }

  private async _downloadRegisteredCert(gatewayUrl: string, aid: string): Promise<string | null> {
    const certUrl = _gatewayHttpUrl(gatewayUrl, `/pki/cert/${aid}`);
    try {
      let certPem: string;
      if (this._net) {
        certPem = await (this._net as any).httpGetText(certUrl, 5000);
      } else {
        certPem = await _httpGet(certUrl, this._verifySsl);
      }
      if (!certPem || !certPem.includes('BEGIN CERTIFICATE')) return null;
      return certPem;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes('404') || msg.toLowerCase().includes('not found')) return null;
      throw new AuthError(`failed to fetch ${certUrl}: ${msg}`);
    }
  }

  private async _createAid(gatewayUrl: string, identity: IdentityRecord): Promise<JsonObject> {
    const response = await this._shortRpc(gatewayUrl, 'auth.create_aid', {
      aid: identity.aid,
      public_key: identity.public_key_der_b64,
      curve: identity.curve || 'P-256',
    });
    return { cert: response.cert };
  }

  private async _shortRpc(gatewayUrl: string, method: string, params: RpcParams): Promise<JsonObject> {
    this._logger.debug(`_shortRpc enter: method=${method}, gateway=${gatewayUrl}`);
    const ws = await _defaultConnectionFactory(gatewayUrl);
    try {
      await this._wsRecv(ws);
      const payload = JSON.stringify({ jsonrpc: '2.0', id: `pre-${method}`, method, params });
      this._logger.debug(`short RPC request full: ${payload}`);
      ws.send(payload);
      const raw = await this._wsRecv(ws);
      const message = typeof raw === 'string' ? JSON.parse(raw) : raw;
      this._logger.debug(`short RPC response full: method=${method} ${JSON.stringify(message)}`);
      if (message.error) throw mapRemoteError(message.error);
      const result = isJsonObject(message.result) ? message.result : null;
      if (result === null) throw new ValidationError(`invalid pre-auth response for ${method}`);
      if (result.success === false) throw new AuthError(String(result.error || `${method} failed`));
      return result;
    } finally {
      try { ws.close(); } catch { /* ignore */ }
    }
  }

  private _wsRecv(ws: WebSocket): Promise<string> {
    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => reject(new AuthError('websocket recv timeout')), 10000);
      const handler = (data: WebSocket.RawData) => {
        clearTimeout(timer);
        ws.off('message', handler);
        ws.off('error', errHandler);
        if (Buffer.isBuffer(data)) resolve(data.toString('utf-8'));
        else if (data instanceof ArrayBuffer) resolve(Buffer.from(data).toString('utf-8'));
        else resolve(String(data));
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

  private _assertCertMatchesLocalKeypair(identity: IdentityRecord): void {
    const aid = identity.aid ?? '?';
    const certPem = identity.cert as string | undefined;
    const localPubB64 = identity.public_key_der_b64 as string | undefined;
    if (!certPem || !localPubB64) {
      throw new AuthError(`identity for aid ${aid} missing cert or public key`);
    }
    let certPubDer: Buffer;
    let localPubDer: Buffer;
    try {
      const cert = _loadX509(certPem);
      certPubDer = _extractPublicKey(cert).export({ type: 'spki', format: 'der' }) as Buffer;
      localPubDer = Buffer.from(localPubB64, 'base64');
    } catch (e) {
      throw new AuthError(`failed to parse local cert/keypair for aid ${aid}: ${e instanceof Error ? e.message : String(e)}`);
    }
    if (!certPubDer.equals(localPubDer)) {
      throw new AuthError(`local certificate public key does not match local keypair for aid ${aid}`);
    }
  }

  private _persistIdentity(identity: IdentityRecord): void {
    const aid = String(identity.aid ?? '');
    if (!aid) return;
    const certPem = String(identity.cert ?? '');
    if (certPem) this._keystore.saveCert(aid, certPem);
  }
}
