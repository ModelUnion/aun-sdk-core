/**
 * RegisterFlow — AID 注册流程。
 * 与 TS SDK register-flow.ts 对齐。浏览器环境使用原生 WebSocket + fetch。
 */

import type { KeyStore } from './keystore/index.js';
import type { CryptoProvider } from './crypto.js';
import type { ModuleLogger } from './logger.js';
import { AuthError, IdentityConflictError, ValidationError, mapRemoteError } from './errors.js';
import { isJsonObject, type IdentityRecord, type KeyPairRecord, type JsonObject, type RpcParams } from './types.js';
import { uint8ToBase64, pemToArrayBuffer } from './crypto.js';
import { parseCertMetadata, verifySignatureWithCert } from './cert-utils.js';

const _noopLog: ModuleLogger = { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} };
const AID_NAME_RE = /^[a-z0-9_][a-z0-9_-]{3,63}$/;

type PendingKeyStore = KeyStore & {
  pendingIdentityDir(aid: string): Promise<string>;
  listPendingIdentityDirs(aid: string): Promise<string[]>;
  savePendingKeyPair(handle: string, aid: string, keyPair: KeyPairRecord): Promise<void>;
  loadPendingKeyPair(handle: string, aid: string): Promise<KeyPairRecord | null>;
  savePendingCert(handle: string, certPem: string): Promise<void>;
  promotePendingIdentity(handle: string, aid: string): Promise<string>;
  discardPendingIdentity?(handle: string): Promise<void>;
};

export interface RegisterResult {
  aid: string;
  cert: string;
  private_key_pem: string;
  public_key_der_b64: string;
  curve: string;
}

/** 将 WebSocket URL 转为对应的 HTTP URL */
function _gatewayHttpUrl(gatewayUrl: string, path: string): string {
  try {
    const parsed = new URL(gatewayUrl);
    const scheme = parsed.protocol === 'wss:' ? 'https:' : 'http:';
    return `${scheme}//${parsed.host}${path}`;
  } catch {
    return gatewayUrl.replace(/^wss:/, 'https:').replace(/^ws:/, 'http:') + path;
  }
}

/** 从证书 PEM 中提取 SPKI 公钥 DER base64（简化版，复用 auth.ts 的 parseCertDer 逻辑） */
function _extractSpkiB64FromPem(certPem: string): string {
  // 复用 auth.ts 中已有的 parseCertDer 逻辑，但 auth.ts 未导出。
  // 这里用最小化的 DER 解析提取 SPKI 字节。
  const der = new Uint8Array(pemToArrayBuffer(certPem));

  function readLen(data: Uint8Array, offset: number): { value: number; lenBytes: number } {
    const first = data[offset]!;
    if (!(first & 0x80)) return { value: first, lenBytes: 1 };
    const n = first & 0x7f;
    let v = 0;
    for (let i = 0; i < n; i++) v = (v << 8) | data[offset + 1 + i]!;
    return { value: v, lenBytes: 1 + n };
  }

  function skipTlv(data: Uint8Array, offset: number): number {
    const len = readLen(data, offset + 1);
    return offset + 1 + len.lenBytes + len.value;
  }

  // cert SEQUENCE → tbs SEQUENCE → skip version/serial/sigAlg/issuer/validity/subject → spki
  const certLen = readLen(der, 1);
  const tbsStart = 1 + certLen.lenBytes;
  const tbsLen = readLen(der, tbsStart + 1);
  let pos = tbsStart + 1 + tbsLen.lenBytes;
  if (der[pos] === 0xa0) pos = skipTlv(der, pos); // version
  pos = skipTlv(der, pos); // serial
  pos = skipTlv(der, pos); // sigAlg
  pos = skipTlv(der, pos); // issuer
  pos = skipTlv(der, pos); // validity
  pos = skipTlv(der, pos); // subject
  // now at spki SEQUENCE
  const spkiLen = readLen(der, pos + 1);
  const spkiEnd = pos + 1 + spkiLen.lenBytes + spkiLen.value;
  return uint8ToBase64(der.slice(pos, spkiEnd));
}

export class RegisterFlow {
  private _keystore: PendingKeyStore;
  private _crypto: CryptoProvider;
  private _logger: ModuleLogger;

  constructor(opts: {
    keystore: PendingKeyStore;
    crypto: CryptoProvider;
    verifySsl?: boolean;
    logger?: ModuleLogger;
  }) {
    this._keystore = opts.keystore;
    this._crypto = opts.crypto;
    this._logger = opts.logger ?? _noopLog;
    // verifySsl 在浏览器环境不可控，忽略
  }

  validateAidName(aid: string): void {
    RegisterFlow.validateAidName(aid);
  }

  static validateAidName(aid: string): void {
    const name = aid.includes('.') ? aid.split('.')[0]! : aid;
    if (!AID_NAME_RE.test(name)) {
      throw new ValidationError(
        `Invalid AID name '${name}': must be 4-64 characters, only [a-z0-9_-], cannot start with '-'`,
      );
    }
    if (name.startsWith('guest')) {
      throw new ValidationError("AID name must not start with 'guest'");
    }
  }

  async fetchPeerCert(gatewayUrl: string, aid: string): Promise<string | null> {
    return this._downloadRegisteredCert(gatewayUrl, aid);
  }

  async shortRpc(gatewayUrl: string, method: string, params: RpcParams): Promise<JsonObject> {
    return this._shortRpc(gatewayUrl, method, params);
  }

  async generateIdentity(): Promise<KeyPairRecord> {
    return await this._crypto.generateIdentity() as KeyPairRecord;
  }

  newClientNonce(): string {
    return this._crypto.newClientNonce();
  }

  async verifyPhase1Response(gatewayUrl: string, result: JsonObject, clientNonce: string): Promise<void> {
    void gatewayUrl;
    const authCertPem = String(result.auth_cert ?? '');
    const signatureB64 = String(result.client_nonce_signature ?? '');
    if (!authCertPem) throw new AuthError('aid_login1 missing auth_cert');
    if (!signatureB64) throw new AuthError('aid_login1 missing client_nonce_signature');

    const metadata = parseCertMetadata(authCertPem);
    const now = Date.now();
    if (metadata.notBefore.getTime() > now) throw new AuthError('aid_login1 auth certificate is not_yet_valid');
    if (metadata.notAfter.getTime() < now) throw new AuthError('aid_login1 auth certificate is expired');

    const valid = await verifySignatureWithCert(
      authCertPem,
      signatureB64,
      new TextEncoder().encode(clientNonce),
    );
    if (!valid) throw new AuthError('aid_login1 server auth signature verification failed');
  }

  reloadTrustedRoots(): number {
    return 0;
  }

  async registerAid(gatewayUrl: string, aid: string): Promise<RegisterResult> {
    const tStart = Date.now();
    this.validateAidName(aid);
    this._logger.debug(`registerAid enter: aid=${aid}, gateway=${gatewayUrl}`);
    try {
      // Step 1: 本地已有 keypair → 幂等/恢复
      const existing = await this._keystore.loadIdentity(aid);
      if (existing && existing.private_key_pem && existing.public_key_der_b64) {
        this._logger.debug(`registerAid: local keypair exists, checking server: aid=${aid}`);
        const localPubB64 = String(existing.public_key_der_b64);
        const serverCertPem = await this._downloadRegisteredCert(gatewayUrl, aid);
        if (serverCertPem) {
          // 服务端已注册 → 比对公钥
          const serverPubB64 = _extractSpkiB64FromPem(serverCertPem);
          if (serverPubB64 !== localPubB64) {
            throw new IdentityConflictError(
              `AID '${aid}' is registered by another party on server (public key mismatch). Choose a different name.`,
            );
          }
          this._logger.info(`registerAid: idempotent return for already-registered AID: aid=${aid}`);
          if (!existing.cert) {
            existing.cert = serverCertPem;
            await this._persistIdentity(existing);
          }
          this._logger.debug(`registerAid exit (idempotent): elapsed=${Date.now() - tStart}ms aid=${aid}`);
          return {
            aid,
            cert: serverCertPem,
            private_key_pem: String(existing.private_key_pem),
            public_key_der_b64: localPubB64,
            curve: String(existing.curve ?? 'P-256'),
          };
        } else {
          // 服务端无记录 → 用现有 keypair 发起注册
          this._logger.debug(`registerAid: server has no record, registering with existing keypair: aid=${aid}`);
          const created = await this._createAid(gatewayUrl, existing);
          const certPem = String(created.cert ?? '');
          if (!certPem) throw new AuthError(`registerAid: server response missing cert for ${aid}`);
          existing.cert = certPem;
          this._assertCertMatchesLocalKeypair(existing);
          await this._persistIdentity(existing);
          this._logger.debug(`registerAid exit (recovered): elapsed=${Date.now() - tStart}ms aid=${aid}`);
          return {
            aid,
            cert: certPem,
            private_key_pem: String(existing.private_key_pem),
            public_key_der_b64: localPubB64,
            curve: String(existing.curve ?? 'P-256'),
          };
        }
      }

      // Step 2: 检查 pending 残留（崩溃/页面关闭恢复）
      const recovered = await this._tryRecoverPendingRegistration(gatewayUrl, aid);
      if (recovered !== null) {
        this._logger.info(`registerAid recovered from pending: aid=${aid}`);
        return recovered;
      }

      // Step 3: 服务端查重
      const existingCert = await this._downloadRegisteredCert(gatewayUrl, aid);
      if (existingCert) {
        throw new IdentityConflictError(
          `AID '${aid}' is already registered on server. Choose a different name, or if you own the keypair use a recovery flow.`,
        );
      }

      // Step 4: 生成 keypair，并先写入 pending 加密记录
      const identity = await this._crypto.generateIdentity() as IdentityRecord;
      identity.aid = aid;
      const pendingStore = this._pendingStore();
      const pendingHandle = await pendingStore.pendingIdentityDir(aid);
      await pendingStore.savePendingKeyPair(pendingHandle, aid, identity);

      // Step 5: 服务端注册拿 cert；失败时保留 pending 供后续恢复
      let created: JsonObject;
      try {
        created = await this._createAid(gatewayUrl, identity);
      } catch (e) {
        this._logger.warn(`registerAid RPC failed (pending kept for recovery): aid=${aid}, pending=${pendingHandle}, error=${e instanceof Error ? e.message : String(e)}`);
        throw e;
      }
      const certPem = String(created.cert ?? '');
      if (!certPem) throw new AuthError(`registerAid: server response missing cert for ${aid}`);
      identity.cert = certPem;

      // Step 6: 校验 cert 公钥 == 本地公钥
      this._assertCertMatchesLocalKeypair(identity);

      // Step 7/8: 写 pending cert，再 promote 到正式 identity
      await pendingStore.savePendingCert(pendingHandle, certPem);
      try {
        await pendingStore.promotePendingIdentity(pendingHandle, aid);
      } catch (e) {
        throw new IdentityConflictError(
          `AID '${aid}' was created by another process during registration; pending record kept for cleanup.`,
        );
      }

      // Step 9: 持久化非私钥字段；私钥已随 pending promote 转正
      await this._persistIdentity(identity);
      this._logger.debug(`registerAid exit: elapsed=${Date.now() - tStart}ms aid=${aid}`);
      return {
        aid,
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
    return store as PendingKeyStore;
  }

  private async _tryRecoverPendingRegistration(gatewayUrl: string, aid: string): Promise<RegisterResult | null> {
    const pendingStore = this._pendingStore();
    const handles = await pendingStore.listPendingIdentityDirs(aid);
    for (const handle of handles) {
      let keyPair: IdentityRecord | null;
      try {
        keyPair = await pendingStore.loadPendingKeyPair(handle, aid);
      } catch (exc) {
        this._logger.warn(`pending identity keypair load failed; keeping pending for retry: aid=${aid}, pending=${handle}, error=${exc instanceof Error ? exc.message : String(exc)}`);
        throw exc;
      }
      const privateKeyPem = String(keyPair?.private_key_pem ?? '');
      const publicKeyDerB64 = String(keyPair?.public_key_der_b64 ?? '');
      if (!privateKeyPem || !publicKeyDerB64) {
        await pendingStore.discardPendingIdentity?.(handle);
        continue;
      }

      const serverCertPem = await this._downloadRegisteredCert(gatewayUrl, aid);
      if (!serverCertPem) {
        this._logger.info(`pending record found but server has no registration; cleaning up: ${handle}`);
        await pendingStore.discardPendingIdentity?.(handle);
        return null;
      }

      const serverPubB64 = _extractSpkiB64FromPem(serverCertPem);
      if (serverPubB64 !== publicKeyDerB64) {
        await pendingStore.discardPendingIdentity?.(handle);
        throw new IdentityConflictError(
          `AID '${aid}' has been registered by another party while local pending registration was incomplete; local pending key discarded.`,
        );
      }

      const identity: IdentityRecord = {
        aid,
        cert: serverCertPem,
        private_key_pem: privateKeyPem,
        public_key_der_b64: publicKeyDerB64,
        curve: String(keyPair?.curve ?? 'P-256'),
      };
      await pendingStore.savePendingKeyPair(handle, aid, identity);
      await pendingStore.savePendingCert(handle, serverCertPem);
      try {
        await pendingStore.promotePendingIdentity(handle, aid);
      } catch (e) {
        throw new IdentityConflictError(
          `AID '${aid}' was created by another process during recovery; pending record kept for cleanup.`,
        );
      }
      await this._persistIdentity(identity);
      return {
        aid,
        cert: serverCertPem,
        private_key_pem: privateKeyPem,
        public_key_der_b64: publicKeyDerB64,
        curve: String(keyPair?.curve ?? 'P-256'),
      };
    }
    return null;
  }

  private async _downloadRegisteredCert(gatewayUrl: string, aid: string): Promise<string | null> {
    const certUrl = _gatewayHttpUrl(gatewayUrl, `/pki/cert/${aid}`);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
      const resp = await fetch(certUrl, { signal: controller.signal });
      if (!resp.ok) return null;
      const certPem = await resp.text();
      if (!certPem || !certPem.includes('BEGIN CERTIFICATE')) return null;
      return certPem;
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  private async _createAid(gatewayUrl: string, identity: IdentityRecord): Promise<JsonObject> {
    const response = await this._shortRpc(gatewayUrl, 'auth.create_aid', {
      aid: identity.aid,
      public_key: identity.public_key_der_b64,
      curve: identity.curve ?? 'P-256',
    });
    return { cert: response.cert };
  }

  private _shortRpc(gatewayUrl: string, method: string, params: RpcParams): Promise<JsonObject> {
    return new Promise((resolve, reject) => {
      let ws: WebSocket;
      try {
        ws = new WebSocket(gatewayUrl);
      } catch {
        reject(new AuthError(`WebSocket 连接失败: ${gatewayUrl}`));
        return;
      }
      let receivedChallenge = false;
      const timeout = globalThis.setTimeout(() => {
        try { ws.close(); } catch { /* 忽略 */ }
        reject(new AuthError(`shortRpc 超时: ${method}`));
      }, 10000);

      ws.onerror = () => {
        globalThis.clearTimeout(timeout);
        reject(new AuthError(`WebSocket 连接错误: ${gatewayUrl}`));
      };

      ws.onmessage = (event) => {
        try {
          const msg = typeof event.data === 'string' ? JSON.parse(event.data) : event.data;
          if (!receivedChallenge) {
            receivedChallenge = true;
            ws.send(JSON.stringify({ jsonrpc: '2.0', id: `pre-${method}`, method, params }));
            return;
          }
          globalThis.clearTimeout(timeout);
          try { ws.close(); } catch { /* 忽略 */ }
          if (msg.error) { reject(mapRemoteError(msg.error)); return; }
          const result = msg.result;
          if (!isJsonObject(result)) { reject(new ValidationError(`invalid pre-auth response for ${method}`)); return; }
          if (result.success === false) { reject(new AuthError(String(result.error ?? `${method} failed`))); return; }
          resolve(result);
        } catch (e) {
          globalThis.clearTimeout(timeout);
          try { ws.close(); } catch { /* 忽略 */ }
          reject(e instanceof Error ? e : new AuthError(String(e)));
        }
      };
    });
  }

  private _assertCertMatchesLocalKeypair(identity: IdentityRecord): void {
    const aid = identity.aid ?? '?';
    const certPem = identity.cert as string | undefined;
    const localPubB64 = identity.public_key_der_b64 as string | undefined;
    if (!certPem || !localPubB64) {
      throw new AuthError(`identity for aid ${aid} missing cert or public key`);
    }
    const certPubB64 = _extractSpkiB64FromPem(certPem);
    if (certPubB64 !== localPubB64) {
      throw new AuthError(`local certificate public key does not match local keypair for aid ${aid}`);
    }
  }

  private async _persistIdentity(identity: IdentityRecord): Promise<void> {
    const aid = String(identity.aid ?? '');
    if (!aid) return;
    const certPem = String(identity.cert ?? '');
    if (certPem) await this._keystore.saveCert(aid, certPem);
  }
}
