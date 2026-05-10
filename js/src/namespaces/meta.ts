// ── MetaNamespace（元数据命名空间 — 浏览器完整实现）──────────────
// 与 TS SDK MetaNamespace 对齐，使用 WebCrypto + IndexedDB 替代 node:crypto + fs。

import type { AUNClient } from '../client.js';
import { ValidationError } from '../errors.js';
import type { JsonObject, JsonValue, RpcParams, RpcResult } from '../types.js';
import {
  pemToArrayBuffer, base64ToUint8, uint8ToBase64, toBufferSource,
} from '../crypto.js';

/** 全局信任根列表端点 */
const AUTHORITY_ENDPOINT = 'https://trust.aun.network/.well-known/aun/trust-roots.json';
/** 允许的最大时钟偏移（秒） */
const MAX_CLOCK_SKEW = 300;

/** 访问 AUNClient 私有字段的桥接接口 */
interface MetaClientBridge {
  _gatewayUrl: string | null;
  configModel: { discoveryPort?: number | null; verifySsl?: boolean };
  _keystore: any;
  _auth: { reload_trusted_roots?: () => number; reloadTrustedRoots?: () => number };
  _rootCerts?: string[];
  call: (method: string, params: RpcParams) => Promise<RpcResult>;
}

/**
 * Meta 命名空间 — 心跳、状态和信任根管理。
 *
 * 浏览器环境适配要点：
 * - 签名验证使用 SubtleCrypto（异步）
 * - 指纹计算使用 SubtleCrypto SHA-256
 * - 持久化通过 keystore（IndexedDB）的可选方法
 * - 无文件系统访问
 */
export class MetaNamespace {
  private _client: AUNClient;

  constructor(client: AUNClient) {
    this._client = client;
  }

  private get _internal(): MetaClientBridge {
    return this._client as any;
  }

  // ── RPC 直通 ──────────────────────────────────────────────

  async ping(params?: RpcParams): Promise<RpcResult> {
    return await this._client.call('meta.ping', params ?? {});
  }

  async status(params?: RpcParams): Promise<RpcResult> {
    return await this._client.call('meta.status', params ?? {});
  }

  async trustRoots(params?: RpcParams): Promise<RpcResult> {
    return await this._client.call('meta.trust_roots', params ?? {});
  }

  // ── 信任根下载 ────────────────────────────────────────────

  async downloadTrustRoots(opts?: {
    url?: string;
    issuer?: string;
    gateway_url?: string;
    timeout?: number;
  }): Promise<JsonObject> {
    const target = this._resolveTrustRootsUrl(
      opts?.url,
      opts?.issuer,
      opts?.gateway_url,
    );
    if (!target.toLowerCase().startsWith('https://') && !target.toLowerCase().startsWith('http://')) {
      throw new ValidationError('trust roots url must be http(s)');
    }
    const timeoutMs = (opts?.timeout ?? 10) * 1000;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(target, {
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new ValidationError(`trust roots download failed: HTTP ${response.status}`);
      }
      const payload = await response.json();
      if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        throw new ValidationError('trust roots endpoint returned non-object JSON');
      }
      return payload as JsonObject;
    } finally {
      clearTimeout(timer);
    }
  }

  async downloadIssuerRootCert(
    issuer: string,
    opts?: { url?: string; timeout?: number },
  ): Promise<string> {
    const normalizedIssuer = MetaNamespace._validateIssuer(issuer);
    const target = opts?.url?.trim() || this._issuerRootCertUrl(normalizedIssuer);
    if (!target.toLowerCase().startsWith('https://') && !target.toLowerCase().startsWith('http://')) {
      throw new ValidationError('issuer root certificate url must be http(s)');
    }
    const timeoutMs = (opts?.timeout ?? 10) * 1000;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(target, {
        headers: { Accept: 'application/x-pem-file,text/plain' },
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new ValidationError(`issuer root cert download failed: HTTP ${response.status}`);
      }
      const certPem = (await response.text()).trim();
      MetaNamespace._validateCertPem(certPem, normalizedIssuer);
      return certPem + '\n';
    } finally {
      clearTimeout(timer);
    }
  }

  // ── 信任根验证 ────────────────────────────────────────────

  async verifyTrustRoots(
    trustList: JsonObject,
    opts?: {
      authority_cert_pem?: string;
      authority_public_key_pem?: string;
      allow_unsigned?: boolean;
    },
  ): Promise<JsonObject> {
    if (!trustList || typeof trustList !== 'object') {
      throw new ValidationError('trust roots list must be a JSON object');
    }
    const signature = String(trustList.authority_signature ?? '').trim();
    if (!signature && !opts?.allow_unsigned) {
      throw new ValidationError('trust roots list missing authority_signature');
    }
    MetaNamespace._validateListMetadata(trustList);

    // 签名验证（WebCrypto 异步）
    if (signature) {
      const publicKey = await this._loadAuthorityPublicKey(
        opts?.authority_cert_pem,
        opts?.authority_public_key_pem,
        trustList,
      );
      const signedPayload = MetaNamespace._canonicalSignedPayload(trustList);
      const sigBytes = MetaNamespace._decodeSignature(signature);
      const ok = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        publicKey,
        toBufferSource(sigBytes),
        toBufferSource(signedPayload),
      );
      if (!ok) {
        throw new ValidationError('trust roots authority_signature verification failed');
      }
    }

    const roots = MetaNamespace._extractRootEntries(trustList);
    const imported: Array<{ id: string; cert_pem: string; fingerprint_sha256: string }> = [];
    const skipped: Array<{ id: string; reason: string }> = [];

    for (const item of roots) {
      const status = String(item.status ?? 'active').trim().toLowerCase();
      const certPem = String(item.certificate ?? item.cert_pem ?? '').trim();
      const rootId = String(item.id ?? item.agentid ?? '').trim();

      if (status !== 'active') {
        skipped.push({ id: rootId, reason: `status=${status}` });
        continue;
      }

      MetaNamespace._validateCertPem(certPem, rootId || 'root');
      const fingerprint = await MetaNamespace._certFingerprint(certPem);
      const expectedFp = MetaNamespace._normalizeFingerprint(item.fingerprint_sha256);
      if (expectedFp.length !== 64) {
        throw new ValidationError(`root certificate missing or invalid fingerprint_sha256: ${rootId || fingerprint}`);
      }
      if (expectedFp !== fingerprint) {
        throw new ValidationError(`root certificate fingerprint mismatch: ${rootId || fingerprint}`);
      }
      imported.push({ id: rootId || fingerprint, cert_pem: certPem, fingerprint_sha256: fingerprint });
    }

    if (imported.length === 0) {
      throw new ValidationError('trust roots list contains no active root certificates');
    }
    return { imported, skipped, count: imported.length };
  }

  // ── 信任根导入 ────────────────────────────────────────────

  async importTrustRoots(
    trustList: JsonObject,
    opts?: {
      authority_cert_pem?: string;
      authority_public_key_pem?: string;
      allow_unsigned?: boolean;
    },
  ): Promise<JsonObject> {
    const verified = await this.verifyTrustRoots(trustList, opts) as any;
    await this._enforceMonotonicVersion(trustList);

    const ks = this._internal._keystore;
    // 持久化：优先使用 keystore 提供的 saveTrustRoots 方法
    let bundlePath = '';
    if (typeof ks.saveTrustRoots === 'function') {
      bundlePath = await ks.saveTrustRoots(trustList, verified.imported);
    } else {
      console.warn('[MetaNamespace] keystore 没有 saveTrustRoots 方法，跳过持久化');
    }

    const auth = this._internal._auth;
    const reloaded = auth.reloadTrustedRoots?.() ?? auth.reload_trusted_roots?.() ?? 0;

    return {
      imported: verified.count,
      skipped: verified.skipped,
      bundle_path: bundlePath,
      reloaded_roots: reloaded,
      fingerprints: verified.imported.map((i: any) => i.fingerprint_sha256),
    };
  }

  async refreshTrustRoots(opts?: {
    url?: string;
    issuer?: string;
    gateway_url?: string;
    authority_cert_pem?: string;
    authority_public_key_pem?: string;
    allow_unsigned?: boolean;
    timeout?: number;
  }): Promise<JsonObject> {
    const sourceUrl = this._resolveTrustRootsUrl(opts?.url, opts?.issuer, opts?.gateway_url);
    const trustList = await this.downloadTrustRoots({ url: sourceUrl, timeout: opts?.timeout });
    const result = await this.importTrustRoots(trustList, {
      authority_cert_pem: opts?.authority_cert_pem,
      authority_public_key_pem: opts?.authority_public_key_pem,
      allow_unsigned: opts?.allow_unsigned,
    });
    (result as any).source_url = sourceUrl;
    return result;
  }

  async updateIssuerRootCert(
    issuer: string,
    opts?: {
      cert_pem?: string;
      url?: string;
      trust_list?: JsonObject;
      authority_cert_pem?: string;
      authority_public_key_pem?: string;
      allow_unsigned?: boolean;
      timeout?: number;
    },
  ): Promise<JsonObject> {
    const normalizedIssuer = MetaNamespace._validateIssuer(issuer);
    const sourceUrl = opts?.url?.trim() || this._issuerRootCertUrl(normalizedIssuer);

    let rootPem = opts?.cert_pem?.trim() ? opts.cert_pem.trim() + '\n' : '';
    if (!rootPem) {
      rootPem = await this.downloadIssuerRootCert(normalizedIssuer, { url: sourceUrl, timeout: opts?.timeout });
    }

    MetaNamespace._validateCertPem(rootPem, normalizedIssuer);
    const fingerprint = await MetaNamespace._certFingerprint(rootPem);

    // 获取信任列表：优先参数 → 本地 → 远程下载
    let effectiveTrustList = opts?.trust_list ?? await this._loadLocalTrustList();
    let trustSource = 'local';
    if (!effectiveTrustList) {
      effectiveTrustList = await this.downloadTrustRoots({ issuer: normalizedIssuer, timeout: opts?.timeout });
      trustSource = this._issuerTrustRootUrl(normalizedIssuer);
    }

    const verified = await this.verifyTrustRoots(effectiveTrustList, {
      authority_cert_pem: opts?.authority_cert_pem,
      authority_public_key_pem: opts?.authority_public_key_pem,
      allow_unsigned: opts?.allow_unsigned,
    }) as any;
    await this._enforceMonotonicVersion(effectiveTrustList);

    // 交叉验证：下载的证书必须在信任列表中
    const trustedFingerprints = new Set(verified.imported.map((i: any) => i.fingerprint_sha256));
    if (!trustedFingerprints.has(fingerprint)) {
      throw new ValidationError('issuer root certificate is not in trusted root list');
    }

    // 持久化
    const ks = this._internal._keystore;
    let certPath = '';
    let bundlePath = '';
    if (typeof ks.saveIssuerRootCert === 'function') {
      [certPath, bundlePath] = await ks.saveIssuerRootCert(normalizedIssuer, rootPem, fingerprint);
    } else {
      console.warn('[MetaNamespace] keystore 没有 saveIssuerRootCert 方法，跳过持久化');
    }

    const auth = this._internal._auth;
    const reloaded = auth.reloadTrustedRoots?.() ?? auth.reload_trusted_roots?.() ?? 0;

    return {
      issuer: normalizedIssuer,
      fingerprint_sha256: fingerprint,
      cert_path: certPath,
      bundle_path: bundlePath,
      reloaded_roots: reloaded,
      source_url: sourceUrl,
      trust_source: trustSource,
    };
  }

  // ── URL 解析 ──────────────────────────────────────────────

  private _resolveTrustRootsUrl(
    url?: string | null,
    issuer?: string | null,
    gatewayUrl?: string | null,
  ): string {
    const target = (url ?? '').trim();
    if (target) return target;
    if (issuer) return this._issuerTrustRootUrl(issuer);
    const gw = (gatewayUrl ?? this._internal._gatewayUrl ?? '').trim();
    return gw ? this._gatewayTrustRootsUrl(gw) : AUTHORITY_ENDPOINT;
  }

  _issuerTrustRootUrl(issuer: string): string {
    const authority = this._pkiAuthority(issuer);
    return `https://${authority}/trust-root.json`;
  }

  _issuerRootCertUrl(issuer: string): string {
    const authority = this._pkiAuthority(issuer);
    return `https://${authority}/root.crt`;
  }

  private _pkiAuthority(issuer: string): string {
    const normalized = MetaNamespace._validateIssuer(issuer);
    const port = this._internal.configModel.discoveryPort;
    const portSuffix = port && !normalized.includes(':') ? `:${port}` : '';
    return `pki.${normalized}${portSuffix}`;
  }

  _gatewayTrustRootsUrl(gatewayUrl: string): string {
    let parsed: URL;
    try {
      parsed = new URL(gatewayUrl);
    } catch {
      throw new ValidationError('gateway_url must include scheme and host');
    }
    if (!parsed.host) {
      throw new ValidationError('gateway_url must include scheme and host');
    }
    const scheme = ['wss:', 'https:'].includes(parsed.protocol) ? 'https' : 'http';
    return `${scheme}://${parsed.host}/pki/trust-roots.json`;
  }

  // ── 内部辅助 ──────────────────────────────────────────────

  /** 校验 issuer 域名格式 */
  private static _validateIssuer(issuer: string): string {
    const value = (issuer ?? '').trim().toLowerCase();
    if (!value || value.includes('://') || value.includes('/') || value.includes('\\') || value.startsWith('.')) {
      throw new ValidationError('issuer must be a domain name');
    }
    return value;
  }

  /** 校验信任列表元数据（版本、时间戳） */
  private static _validateListMetadata(trustList: JsonObject): void {
    const version = trustList.version;
    if (typeof version !== 'number' || !Number.isInteger(version) || version < 0) {
      throw new ValidationError('trust roots list version must be a non-negative integer');
    }
    const issuedAt = MetaNamespace._parseTimestamp(trustList.issued_at, 'issued_at');
    const nextUpdate = MetaNamespace._parseTimestamp(trustList.next_update, 'next_update');
    if (nextUpdate < issuedAt) {
      throw new ValidationError('trust roots list next_update must not be earlier than issued_at');
    }
    if (issuedAt > Date.now() + MAX_CLOCK_SKEW * 1000) {
      throw new ValidationError('trust roots list issued_at is too far in the future');
    }
  }

  private static _parseTimestamp(value: unknown, field: string): number {
    const text = String(value ?? '').trim();
    if (!text) throw new ValidationError(`trust roots list missing ${field}`);
    const ts = new Date(text).getTime();
    if (isNaN(ts)) throw new ValidationError(`trust roots list ${field} must be ISO-8601`);
    return ts;
  }

  /** 构建用于签名验证的规范化 JSON 载荷 */
  private static _canonicalSignedPayload(trustList: JsonObject): Uint8Array {
    const payload = { ...trustList };
    delete payload.authority_signature;
    const canonical = MetaNamespace._stableStringify(payload);
    return new TextEncoder().encode(canonical);
  }

  /** 递归稳定排序 JSON 序列化 */
  private static _stableStringify(obj: any): string {
    if (obj === null || obj === undefined) return JSON.stringify(obj);
    if (typeof obj !== 'object') return JSON.stringify(obj);
    if (Array.isArray(obj)) {
      return '[' + obj.map(v => MetaNamespace._stableStringify(v)).join(',') + ']';
    }
    const keys = Object.keys(obj).sort();
    const pairs = keys.map(k => JSON.stringify(k) + ':' + MetaNamespace._stableStringify(obj[k]));
    return '{' + pairs.join(',') + '}';
  }

  /** 解码 base64 编码的签名 */
  private static _decodeSignature(signature: string): Uint8Array {
    let value = signature.trim();
    if (value.startsWith('base64:')) {
      value = value.slice(7);
    }
    // 处理 URL-safe base64 并补齐 padding
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - (normalized.length % 4)) % 4);
    return base64ToUint8(normalized + padding);
  }

  /** 提取信任列表中的根 CA 条目 */
  private static _extractRootEntries(trustList: JsonObject): any[] {
    const roots = trustList.root_cas;
    if (Array.isArray(roots)) {
      return roots.filter(item => item && typeof item === 'object');
    }
    const legacy = trustList.roots;
    if (Array.isArray(legacy)) {
      return legacy
        .filter(item => item && typeof item === 'object')
        .map((item: any) => ({
          id: item.agentid ?? item.id ?? item.cert_sn,
          certificate: item.cert_pem ?? item.certificate,
          fingerprint_sha256: item.fingerprint_sha256,
          status: item.status ?? 'active',
        }));
    }
    throw new ValidationError('trust roots list missing root_cas');
  }

  /** 规范化指纹字符串（去除前缀和分隔符） */
  private static _normalizeFingerprint(value: unknown): string {
    let text = String(value ?? '').trim().toLowerCase();
    if (text.startsWith('sha256:')) text = text.slice(7);
    return text.replace(/[^0-9a-f]/g, '');
  }

  /** 计算证书 PEM 的 SHA-256 指纹（纯 hex，不含 sha256: 前缀） */
  private static async _certFingerprint(certPem: string): Promise<string> {
    const der = pemToArrayBuffer(certPem);
    const hash = await crypto.subtle.digest('SHA-256', der);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /** 校验 PEM 格式是否包含 BEGIN CERTIFICATE */
  private static _validateCertPem(certPem: string, rootId: string): void {
    if (!certPem.includes('BEGIN CERTIFICATE')) {
      throw new ValidationError(`root certificate missing PEM data: ${rootId}`);
    }
  }

  /**
   * 加载权威公钥用于签名验证。
   * 浏览器环境：从 PEM 提取 SPKI 并导入为 CryptoKey。
   * 支持 P-256 和 P-384 曲线。
   */
  private async _loadAuthorityPublicKey(
    authorityCertPem?: string | null,
    authorityPublicKeyPem?: string | null,
    trustList?: JsonObject,
  ): Promise<CryptoKey> {
    // 优先使用直接提供的公钥 PEM
    if (authorityPublicKeyPem) {
      return this._importPublicKeyPem(authorityPublicKeyPem);
    }
    // 其次使用证书 PEM 中的公钥
    const candidateCert = authorityCertPem
      || String(trustList?.authority_cert_pem ?? '');
    if (!candidateCert) {
      throw new ValidationError('authority certificate/public key is required to verify trust roots');
    }
    return this._importCertPublicKey(candidateCert);
  }

  /** 从 SPKI PEM 导入公钥（尝试 P-384，降级 P-256） */
  private async _importPublicKeyPem(pem: string): Promise<CryptoKey> {
    const der = pemToArrayBuffer(pem);
    // 尝试 P-384（信任根权威通常用 P-384）
    for (const curve of ['P-384', 'P-256'] as const) {
      try {
        return await crypto.subtle.importKey(
          'spki', der,
          { name: 'ECDSA', namedCurve: curve },
          true, ['verify'],
        );
      } catch { /* 尝试下一条曲线 */ }
    }
    throw new ValidationError('invalid authority public key PEM');
  }

  /**
   * 从证书 PEM 提取公钥并导入。
   * 使用简化 ASN.1 解析提取 SPKI 段。
   */
  private async _importCertPublicKey(certPem: string): Promise<CryptoKey> {
    if (!certPem.includes('BEGIN CERTIFICATE')) {
      throw new ValidationError('invalid authority certificate PEM');
    }
    const certDer = new Uint8Array(pemToArrayBuffer(certPem));
    const spki = this._extractSpkiFromDer(certDer);
    if (!spki) {
      throw new ValidationError('invalid authority certificate PEM');
    }
    // 尝试 P-384 优先（信任根常用），降级 P-256
    for (const curve of ['P-384', 'P-256'] as const) {
      try {
        return await crypto.subtle.importKey(
          'spki', spki,
          { name: 'ECDSA', namedCurve: curve },
          true, ['verify'],
        );
      } catch { /* 尝试下一条曲线 */ }
    }
    throw new ValidationError('invalid authority certificate PEM');
  }

  /**
   * 从 X.509 DER 证书中提取 SubjectPublicKeyInfo。
   * 搜索 EC 公钥 OID (1.2.840.10045.2.1)。
   */
  private _extractSpkiFromDer(certDer: Uint8Array): ArrayBuffer | null {
    // EC 公钥 OID: 06 07 2a 86 48 ce 3d 02 01
    const ecOid = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    for (let i = 0; i < certDer.length - ecOid.length; i++) {
      let match = true;
      for (let j = 0; j < ecOid.length; j++) {
        if (certDer[i + j] !== ecOid[j]) { match = false; break; }
      }
      if (!match) continue;
      // 往前回溯找 SEQUENCE (0x30) 起始
      for (let back = 1; back <= 4; back++) {
        const seqStart = i - back;
        if (seqStart < 0) continue;
        if (certDer[seqStart] !== 0x30) continue;
        const seqLen = this._parseDerLength(certDer, seqStart + 1);
        if (!seqLen) continue;
        const totalLen = 1 + seqLen.lenBytes + seqLen.value;
        if (totalLen < 50 || totalLen > 200) continue;
        return certDer.slice(seqStart, seqStart + totalLen).buffer;
      }
    }
    return null;
  }

  /** 解析 DER 长度字段 */
  private _parseDerLength(data: Uint8Array, offset: number): { value: number; lenBytes: number } | null {
    if (offset >= data.length) return null;
    const first = data[offset];
    if (first < 0x80) return { value: first, lenBytes: 1 };
    const numBytes = first & 0x7f;
    if (numBytes === 0 || numBytes > 4 || offset + 1 + numBytes > data.length) return null;
    let value = 0;
    for (let i = 0; i < numBytes; i++) {
      value = (value << 8) | data[offset + 1 + i];
    }
    return { value, lenBytes: 1 + numBytes };
  }

  /** 版本单调递增检查（通过 keystore 加载已有版本） */
  private async _enforceMonotonicVersion(trustList: JsonObject): Promise<void> {
    const version = trustList.version;
    if (typeof version !== 'number') return;

    const ks = this._internal._keystore;
    if (typeof ks.loadTrustRoots !== 'function') return;

    try {
      const current = await ks.loadTrustRoots();
      const currentVersion = current?.version;
      if (typeof currentVersion === 'number' && version < currentVersion) {
        throw new ValidationError('trust roots list version rollback is not allowed');
      }
    } catch (e) {
      if (e instanceof ValidationError) throw e;
      // keystore 读取失败等情况忽略
    }
  }

  /** 从 keystore 加载本地已存储的信任列表 */
  private async _loadLocalTrustList(): Promise<JsonObject | null> {
    const ks = this._internal._keystore;
    if (typeof ks.loadTrustRoots !== 'function') return null;
    try {
      const payload = await ks.loadTrustRoots();
      if (!payload || typeof payload !== 'object') return null;
      return payload;
    } catch {
      return null;
    }
  }
}
