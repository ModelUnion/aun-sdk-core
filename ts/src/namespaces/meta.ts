/**
 * Meta 命名空间 — 心跳、状态和信任根管理。
 *
 * 与 Python SDK MetaNamespace 完全对齐。
 */

import * as crypto from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { URL } from 'node:url';

import { ValidationError } from '../errors.js';
import type { JsonObject, JsonValue, RpcParams, RpcResult } from '../types.js';
import type { AUNClient } from '../client.js';
import type { ModuleLogger } from '../logger.js';

const AUTHORITY_ENDPOINT = 'https://trust.aun.network/.well-known/aun/trust-roots.json';
const MAX_CLOCK_SKEW = 300; // 秒
const DEFAULT_TIMEOUT_MS = 10_000;

interface MetaClientBridge {
  _gatewayUrl: string | null;
  _configModel: { discoveryPort?: number | null; verifySsl?: boolean };
  _keystore: any;
  _auth: { reload_trusted_roots?: () => number; reloadTrustedRoots?: () => number };
  _rootCerts?: string[];
  _logger: { for: (module: string) => ModuleLogger };
  call: (method: string, params: RpcParams) => Promise<RpcResult>;
}

export class MetaNamespace {
  private _client: AUNClient;
  private _log: ModuleLogger;

  constructor(client: AUNClient) {
    this._client = client;
    this._log = (client as any as MetaClientBridge)._logger.for('aun_core.namespace.meta');
  }

  private get _internal(): MetaClientBridge {
    return this._client as any;
  }

  // ── RPC 直通 ──────────────────────────────────────────────────

  async ping(params?: RpcParams): Promise<RpcResult> {
    this._log.debug('ping called');
    return await this._client.call('meta.ping', params ?? {});
  }

  async status(params?: RpcParams): Promise<RpcResult> {
    this._log.debug('status called');
    return await this._client.call('meta.status', params ?? {});
  }

  async trustRoots(params?: RpcParams): Promise<RpcResult> {
    this._log.debug('trustRoots called');
    return await this._client.call('meta.trust_roots', params ?? {});
  }

  // ── 信任根下载 ────────────────────────────────────────────────

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
    this._log.debug(`downloadTrustRoots start: target=${target} timeout=${timeoutMs}ms`);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(target, {
        headers: { Accept: 'application/json' },
        signal: controller.signal,
      });
      if (!response.ok) {
        this._log.error(`downloadTrustRoots HTTP ${response.status}: target=${target}`);
        throw new ValidationError(`trust roots download failed: HTTP ${response.status}`);
      }
      const payload = await response.json();
      if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        this._log.error(`downloadTrustRoots non-object payload: target=${target}`);
        throw new ValidationError('trust roots endpoint returned non-object JSON');
      }
      this._log.debug(`downloadTrustRoots ok: target=${target} keys=${Object.keys(payload as JsonObject).length}`);
      return payload as JsonObject;
    } catch (error) {
      if (!(error instanceof ValidationError)) {
        this._log.error(`downloadTrustRoots failed: target=${target} err=${error instanceof Error ? error.message : String(error)}`, error instanceof Error ? error : undefined);
      }
      throw error;
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
    this._log.debug(`downloadIssuerRootCert start: issuer=${normalizedIssuer} target=${target}`);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(target, {
        headers: { Accept: 'application/x-pem-file,text/plain' },
        signal: controller.signal,
      });
      if (!response.ok) {
        this._log.error(`downloadIssuerRootCert HTTP ${response.status}: issuer=${normalizedIssuer} target=${target}`);
        throw new ValidationError(`issuer root cert download failed: HTTP ${response.status}`);
      }
      const certPem = (await response.text()).trim();
      MetaNamespace._loadRootCertificate(certPem, normalizedIssuer);
      this._log.info(`issuer root cert downloaded: issuer=${normalizedIssuer}`);
      return certPem + '\n';
    } catch (error) {
      if (!(error instanceof ValidationError)) {
        this._log.error(`downloadIssuerRootCert failed: issuer=${normalizedIssuer} target=${target} err=${error instanceof Error ? error.message : String(error)}`, error instanceof Error ? error : undefined);
      }
      throw error;
    } finally {
      clearTimeout(timer);
    }
  }

  // ── 信任根验证 ────────────────────────────────────────────────

  verifyTrustRoots(
    trustList: JsonObject,
    opts?: {
      authority_cert_pem?: string;
      authority_public_key_pem?: string;
      allow_unsigned?: boolean;
    },
  ): JsonObject {
    if (!trustList || typeof trustList !== 'object') {
      throw new ValidationError('trust roots list must be a JSON object');
    }
    const signature = String(trustList.authority_signature ?? '').trim();
    if (!signature && !opts?.allow_unsigned) {
      throw new ValidationError('trust roots list missing authority_signature');
    }
    MetaNamespace._validateListMetadata(trustList);

    if (signature) {
      const publicKey = this._loadAuthorityPublicKey(
        opts?.authority_cert_pem,
        opts?.authority_public_key_pem,
        trustList,
      );
      const signedPayload = MetaNamespace._canonicalSignedPayload(trustList);
      const sigBytes = MetaNamespace._decodeSignature(signature);
      const ok = crypto.verify(null, signedPayload, publicKey, sigBytes);
      if (!ok) {
        throw new ValidationError('trust roots authority_signature verification failed');
      }
    }

    const roots = MetaNamespace._extractRootEntries(trustList);
    const imported: Array<{ id: string; cert_pem: string; fingerprint_sha256: string }> = [];
    const skipped: Array<{ id: string; reason: string }> = [];
    const now = Date.now() / 1000;

    for (const item of roots) {
      const status = String(item.status ?? 'active').trim().toLowerCase();
      const certPem = String(item.certificate ?? item.cert_pem ?? '').trim();
      const rootId = String(item.id ?? item.agentid ?? '').trim();

      if (status !== 'active') {
        skipped.push({ id: rootId, reason: `status=${status}` });
        continue;
      }

      MetaNamespace._loadRootCertificate(certPem, rootId || 'root');
      const fingerprint = MetaNamespace._certFingerprint(certPem);
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

  // ── 信任根导入 ────────────────────────────────────────────────

  importTrustRoots(
    trustList: JsonObject,
    opts?: {
      authority_cert_pem?: string;
      authority_public_key_pem?: string;
      allow_unsigned?: boolean;
    },
  ): JsonObject {
    const verified = this.verifyTrustRoots(trustList, opts) as any;
    this._enforceMonotonicVersion(trustList);

    const ks = this._internal._keystore;
    const bundlePath = ks.saveTrustRoots
      ? ks.saveTrustRoots(trustList, verified.imported)
      : this._defaultSaveTrustRoots(trustList, verified.imported);

    const auth = this._internal._auth;
    const reloaded = auth.reloadTrustedRoots?.() ?? auth.reload_trusted_roots?.() ?? 0;

    this._log.info(`trust roots imported: count=${verified.count} skipped=${verified.skipped.length} reloaded=${reloaded}`);

    return {
      imported: verified.count,
      skipped: verified.skipped,
      bundle_path: String(bundlePath),
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
    this._log.debug(`refreshTrustRoots start: source=${sourceUrl}`);
    const trustList = await this.downloadTrustRoots({ url: sourceUrl, timeout: opts?.timeout });
    const result = this.importTrustRoots(trustList, {
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

    MetaNamespace._loadRootCertificate(rootPem, normalizedIssuer);
    const fingerprint = MetaNamespace._certFingerprint(rootPem);

    let effectiveTrustList = opts?.trust_list ?? this._loadLocalTrustList();
    let trustSource = 'local';
    if (!effectiveTrustList) {
      effectiveTrustList = await this.downloadTrustRoots({ issuer: normalizedIssuer, timeout: opts?.timeout });
      trustSource = this._issuerTrustRootUrl(normalizedIssuer);
    }

    const verified = this.verifyTrustRoots(effectiveTrustList, {
      authority_cert_pem: opts?.authority_cert_pem,
      authority_public_key_pem: opts?.authority_public_key_pem,
      allow_unsigned: opts?.allow_unsigned,
    }) as any;
    this._enforceMonotonicVersion(effectiveTrustList);

    const trustedFingerprints = new Set(verified.imported.map((i: any) => i.fingerprint_sha256));
    if (!trustedFingerprints.has(fingerprint)) {
      throw new ValidationError('issuer root certificate is not in trusted root list');
    }

    const ks = this._internal._keystore;
    let certPath: string;
    let bundlePath: string;
    if (ks.saveIssuerRootCert) {
      [certPath, bundlePath] = ks.saveIssuerRootCert(normalizedIssuer, rootPem, fingerprint);
    } else {
      [certPath, bundlePath] = this._defaultSaveIssuerRootCert(normalizedIssuer, rootPem, fingerprint);
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

  // ── URL 解析 ──────────────────────────────────────────────────

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
    const port = this._internal._configModel.discoveryPort;
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

  // ── 内部辅助 ──────────────────────────────────────────────────

  private static _validateIssuer(issuer: string): string {
    const value = (issuer ?? '').trim().toLowerCase();
    if (!value || value.includes('://') || value.includes('/') || value.includes('\\') || value.startsWith('.')) {
      throw new ValidationError('issuer must be a domain name');
    }
    return value;
  }

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

  private static _canonicalSignedPayload(trustList: JsonObject): Buffer {
    const payload = { ...trustList };
    delete payload.authority_signature;
    // 规范 JSON：排序 key，无空格
    const sorted = JSON.stringify(payload, Object.keys(payload).sort(), 0)
      .replace(/\n/g, '');
    // 使用稳定排序的 JSON
    return Buffer.from(MetaNamespace._stableStringify(payload), 'utf-8');
  }

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

  private static _decodeSignature(signature: string): Buffer {
    let value = signature.trim();
    if (value.startsWith('base64:')) {
      value = value.slice(7);
    }
    // 补齐 padding，处理 URL-safe base64
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - (normalized.length % 4)) % 4);
    return Buffer.from(normalized + padding, 'base64');
  }

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

  private static _normalizeFingerprint(value: unknown): string {
    let text = String(value ?? '').trim().toLowerCase();
    if (text.startsWith('sha256:')) text = text.slice(7);
    return text.replace(/[^0-9a-f]/g, '');
  }

  private static _certFingerprint(certPem: string): string {
    const b64 = certPem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
    const der = Buffer.from(b64, 'base64');
    return crypto.createHash('sha256').update(der).digest('hex');
  }

  private static _loadRootCertificate(certPem: string, rootId: string): void {
    if (!certPem.includes('BEGIN CERTIFICATE')) {
      throw new ValidationError(`root certificate missing PEM data: ${rootId}`);
    }
  }

  private _loadAuthorityPublicKey(
    authorityCertPem?: string | null,
    authorityPublicKeyPem?: string | null,
    trustList?: JsonObject,
  ): crypto.KeyObject {
    if (authorityPublicKeyPem) {
      try {
        return crypto.createPublicKey(authorityPublicKeyPem);
      } catch (e) {
        throw new ValidationError('invalid authority public key PEM');
      }
    }
    const candidateCert = authorityCertPem
      || String(trustList?.authority_cert_pem ?? '')
      || this._loadLocalAuthorityCert();
    if (!candidateCert) {
      throw new ValidationError('authority certificate/public key is required to verify trust roots');
    }
    try {
      const x509 = new crypto.X509Certificate(candidateCert);
      return x509.publicKey;
    } catch (e) {
      throw new ValidationError('invalid authority certificate PEM');
    }
  }

  private _loadLocalAuthorityCert(): string {
    const ks = this._internal._keystore;
    const candidates = [
      ks.trustRootDir ? join(ks.trustRootDir(), '..', 'authority', 'authority.crt') : null,
      join(__dirname, '..', 'certs', 'authority.crt'),
    ].filter(Boolean) as string[];
    for (const path of candidates) {
      try {
        if (existsSync(path)) return readFileSync(path, 'utf-8');
      } catch { /* ignore */ }
    }
    return '';
  }

  private _enforceMonotonicVersion(trustList: JsonObject): void {
    const version = trustList.version;
    if (typeof version !== 'number') return;

    const ks = this._internal._keystore;
    const trustRootDir = ks.trustRootDir ? ks.trustRootDir() : this._defaultTrustRootDir();
    const jsonPath = join(trustRootDir, 'trust-roots.json');
    if (!existsSync(jsonPath)) return;

    try {
      const current = JSON.parse(readFileSync(jsonPath, 'utf-8'));
      const currentVersion = current?.version;
      if (typeof currentVersion === 'number' && version < currentVersion) {
        throw new ValidationError('trust roots list version rollback is not allowed');
      }
    } catch (e) {
      if (e instanceof ValidationError) throw e;
      // 文件损坏等情况忽略
    }
  }

  private _loadLocalTrustList(): JsonObject | null {
    const ks = this._internal._keystore;
    const trustRootDir = ks.trustRootDir ? ks.trustRootDir() : this._defaultTrustRootDir();
    const jsonPath = join(trustRootDir, 'trust-roots.json');
    if (!existsSync(jsonPath)) return null;
    try {
      const payload = JSON.parse(readFileSync(jsonPath, 'utf-8'));
      if (!payload || typeof payload !== 'object') {
        throw new ValidationError('local trust roots list must be a JSON object');
      }
      return payload;
    } catch (e) {
      if (e instanceof ValidationError) throw e;
      throw new ValidationError('local trust roots list is invalid');
    }
  }

  // ── 默认存储实现（当 keystore 未提供 trust-root 方法时） ──────

  private _defaultTrustRootDir(): string {
    const ks = this._internal._keystore;
    const root = ks._rootPath ?? ks._root ?? '';
    return join(root, 'CA', 'root');
  }

  private _defaultSaveTrustRoots(trustList: JsonObject, imported: any[]): string {
    const dir = this._defaultTrustRootDir();
    mkdirSync(dir, { recursive: true });

    // 保存每个根证书
    for (const item of imported) {
      const safeId = (item.id || item.fingerprint_sha256).replace(/[^a-zA-Z0-9._-]/g, '_');
      writeFileSync(join(dir, `${safeId}.crt`), item.cert_pem, 'utf-8');
    }

    // 生成合并 bundle
    const bundlePath = join(dir, 'trust-roots.pem');
    const bundle = imported.map((i: any) => i.cert_pem.trim()).join('\n') + '\n';
    writeFileSync(bundlePath, bundle, 'utf-8');

    // 保存元数据
    writeFileSync(join(dir, 'trust-roots.json'), JSON.stringify(trustList, null, 2), 'utf-8');

    return bundlePath;
  }

  private _defaultSaveIssuerRootCert(
    issuer: string,
    certPem: string,
    fingerprint: string,
  ): [string, string] {
    const dir = this._defaultTrustRootDir();
    const issuersDir = join(dir, 'issuers');
    mkdirSync(issuersDir, { recursive: true });

    const safeIssuer = issuer.replace(/[^a-zA-Z0-9._-]/g, '_');
    const certPath = join(issuersDir, `${safeIssuer}.root.crt`);
    writeFileSync(certPath, certPem, 'utf-8');

    // 合并进 bundle（去重）
    const bundlePath = join(dir, 'trust-roots.pem');
    let existingPems: string[] = [];
    if (existsSync(bundlePath)) {
      const existing = readFileSync(bundlePath, 'utf-8');
      existingPems = existing.split(/(?=-----BEGIN CERTIFICATE-----)/).filter(p => p.trim());
    }
    // 去重：按指纹
    const existingFingerprints = new Set(existingPems.map(p => MetaNamespace._certFingerprint(p.trim())));
    if (!existingFingerprints.has(fingerprint)) {
      existingPems.push(certPem.trim());
    }
    writeFileSync(bundlePath, existingPems.join('\n') + '\n', 'utf-8');

    return [certPath, bundlePath];
  }
}
