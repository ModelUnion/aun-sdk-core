/**
 * DNS-Resilient 网络层。
 *
 * 所有 HTTP/WebSocket 请求统一经过此模块，提供 DNS 容灾能力：
 * - 正常走域名（利用系统 DNS 缓存和 CDN 调度）
 * - 连接成功后刷新 DNS→IP 映射到 SQLite
 * - DNS 失败时 fallback 到持久化的最后一次成功 IP
 * - IP 直连时设置 TLS SNI + Host header
 */
import * as http from 'node:http';
import * as https from 'node:https';
import * as dns from 'node:dns';
import * as tls from 'node:tls';
import type { ModuleLogger } from './logger.js';

const _noopLogger: ModuleLogger = { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} };

export interface DnsCacheStore {
  saveDnsCache(hostname: string, ip: string, port: number): void;
  loadDnsCache(hostname: string): { ip: string; port: number } | null;
}

function isDnsError(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const code = (err as { code?: string }).code;
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN' || code === 'EAI_FAIL' || code === 'EAI_NONAME') {
    return true;
  }
  const msg = String((err as Error).message ?? '').toLowerCase();
  return msg.includes('getaddrinfo') && (msg.includes('enotfound') || msg.includes('eai_again'));
}

function parseHostPort(url: string): { hostname: string; port: number } {
  const parsed = new URL(url);
  const hostname = parsed.hostname;
  let port = parsed.port ? Number(parsed.port) : (parsed.protocol === 'https:' || parsed.protocol === 'wss:' ? 443 : 80);
  return { hostname, port };
}

function replaceHostWithIP(url: string, ip: string): string {
  const parsed = new URL(url);
  parsed.hostname = ip.includes(':') ? `[${ip}]` : ip;
  return parsed.toString();
}

function resolveIP(hostname: string): Promise<string | null> {
  return new Promise((resolve) => {
    dns.lookup(hostname, (err, address) => {
      resolve(err ? null : address);
    });
  });
}

export class DnsResilientNet {
  private _store: DnsCacheStore | null;
  private _verifySsl: boolean;
  private _logger: ModuleLogger;

  constructor(opts?: { store?: DnsCacheStore; verifySsl?: boolean; logger?: ModuleLogger }) {
    this._store = opts?.store ?? null;
    this._verifySsl = opts?.verifySsl ?? true;
    this._logger = opts?.logger ?? _noopLogger;
  }

  private _saveDnsCache(hostname: string, ip: string, port: number): void {
    if (!this._store || !hostname || !ip) return;
    try {
      this._store.saveDnsCache(hostname, ip, port);
    } catch (exc) {
      this._logger.debug(`dns cache save failed: ${exc}`);
    }
  }

  private _loadDnsCache(hostname: string): { ip: string; port: number } | null {
    if (!this._store || !hostname) return null;
    try {
      return this._store.loadDnsCache(hostname);
    } catch (exc) {
      this._logger.debug(`dns cache load failed: ${exc}`);
      return null;
    }
  }

  private async _refreshDnsCacheAfterSuccess(url: string): Promise<void> {
    const { hostname, port } = parseHostPort(url);
    if (!hostname) return;
    const ip = await resolveIP(hostname);
    if (ip) this._saveDnsCache(hostname, ip, port);
  }

  async httpGet(url: string, timeout = 5_000): Promise<Buffer> {
    const { hostname, port } = parseHostPort(url);

    try {
      const data = await this._doHttpGet(url, undefined, timeout);
      void this._refreshDnsCacheAfterSuccess(url);
      return data;
    } catch (exc) {
      if (!isDnsError(exc)) throw exc;
    }

    this._logger.debug(`DNS failed for ${hostname}, trying cached IP`);
    const cached = this._loadDnsCache(hostname);
    if (!cached) {
      const err = new Error(`DNS failed and no cached IP for ${hostname}`);
      (err as any).code = 'ENOTFOUND';
      throw err;
    }

    const ipUrl = replaceHostWithIP(url, cached.ip);
    return this._doHttpGet(ipUrl, hostname, timeout);
  }

  async httpGetJson(url: string, timeout = 5_000): Promise<Record<string, unknown>> {
    const data = await this.httpGet(url, timeout);
    return JSON.parse(data.toString('utf-8')) as Record<string, unknown>;
  }

  async httpGetText(url: string, timeout = 5_000): Promise<string> {
    const data = await this.httpGet(url, timeout);
    return data.toString('utf-8');
  }

  async httpGetOk(url: string, timeout = 5_000): Promise<boolean> {
    const { hostname, port } = parseHostPort(url);

    try {
      const ok = await this._doHttpGetOk(url, undefined, timeout);
      if (ok) void this._refreshDnsCacheAfterSuccess(url);
      return ok;
    } catch (exc) {
      if (!isDnsError(exc)) return false;
    }

    const cached = this._loadDnsCache(hostname);
    if (!cached) return false;

    const ipUrl = replaceHostWithIP(url, cached.ip);
    try {
      return await this._doHttpGetOk(ipUrl, hostname, timeout);
    } catch {
      return false;
    }
  }

  /** 导出供 WebSocket 连接层使用 */
  get isDnsError() { return isDnsError; }
  get parseHostPort() { return parseHostPort; }
  get replaceHostWithIP() { return replaceHostWithIP; }

  loadDnsCache(hostname: string) { return this._loadDnsCache(hostname); }
  refreshDnsCacheAfterSuccess(url: string) { return this._refreshDnsCacheAfterSuccess(url); }

  private _doHttpGet(url: string, sniHostname: string | undefined, timeout: number): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const mod = parsed.protocol === 'https:' ? https : http;
      const options: https.RequestOptions = { timeout };
      if (!this._verifySsl) {
        options.rejectUnauthorized = false;
      }
      if (sniHostname) {
        options.headers = { Host: sniHostname };
        options.servername = sniHostname;
      }

      const req = mod.get(url, options, (res: http.IncomingMessage) => {
        if (res.statusCode && (res.statusCode < 200 || res.statusCode >= 300)) {
          reject(new Error(`HTTP ${res.statusCode} from ${url}`));
          res.resume();
          return;
        }
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => resolve(Buffer.concat(chunks)));
        res.on('error', reject);
      });
      req.on('error', reject);
      req.on('timeout', () => { req.destroy(); reject(new Error(`timeout fetching ${url}`)); });
    });
  }

  private _doHttpGetOk(url: string, sniHostname: string | undefined, timeout: number): Promise<boolean> {
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const mod = parsed.protocol === 'https:' ? https : http;
      const options: https.RequestOptions = { method: 'GET', timeout };
      if (!this._verifySsl) options.rejectUnauthorized = false;
      if (sniHostname) {
        options.headers = { Host: sniHostname };
        options.servername = sniHostname;
      }

      const req = mod.request(url, options, (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      });
      req.on('error', (err) => {
        if (isDnsError(err)) reject(err);
        else resolve(false);
      });
      req.on('timeout', () => { req.destroy(); resolve(false); });
      req.end();
    });
  }
}

export { isDnsError, parseHostPort, replaceHostWithIP };
