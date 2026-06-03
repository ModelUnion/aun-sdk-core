import * as http from 'node:http';
import * as https from 'node:https';
import { ConnectionError, ValidationError } from './errors.js';
import { isJsonObject, type GatewayDiscoveryDocument, type GatewayEntry, type JsonValue } from './types.js';
import type { ModuleLogger } from './logger.js';
import type { DnsResilientNet } from './net.js';

const _noopLogger: ModuleLogger = { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} };
const _DISCOVERY_RETRY_DELAYS_MS = [50, 100];

function _sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function _errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

function _errorCode(err: unknown): string {
  if (!err || typeof err !== 'object') return '';
  const code = (err as { code?: unknown }).code;
  return typeof code === 'string' ? code.toUpperCase() : '';
}

function _isTransientDiscoveryError(err: unknown): boolean {
  if (err instanceof ValidationError) return false;

  const code = _errorCode(err);
  if (['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'EPIPE', 'EAI_AGAIN', 'ENOTFOUND'].includes(code)) {
    return true;
  }

  const message = _errorMessage(err).toLowerCase();
  if (/^http\s+\d+/.test(message)) return false;
  return (
    message.includes('socket hang up') ||
    message.includes('connection reset') ||
    message.includes('econnreset') ||
    message.includes('econnrefused') ||
    message.includes('etimedout') ||
    message.includes('epipe') ||
    message.includes('timeout fetching') ||
    message.includes('fetch failed') ||
    message.includes('network error') ||
    message.includes('getaddrinfo')
  );
}

function _httpGetJson(url: string, verifySsl: boolean, timeout: number): Promise<JsonValue> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;
    const options: https.RequestOptions = { timeout };
    if (!verifySsl) {
      options.rejectUnauthorized = false;
    }

    const req = mod.get(url, options, (res: http.IncomingMessage) => {
      if (res.statusCode && (res.statusCode < 200 || res.statusCode >= 300)) {
        reject(new Error(`HTTP ${res.statusCode}`));
        res.resume();
        return;
      }
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf-8')) as JsonValue);
        } catch (error) {
          reject(error);
        }
      });
      res.on('error', reject);
    });

    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`timeout fetching ${url}`));
    });
  });
}

function _httpGetOk(url: string, verifySsl: boolean, timeout: number): Promise<boolean> {
  return new Promise((resolve) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;
    const options: https.RequestOptions = { method: 'GET', timeout };
    if (!verifySsl) options.rejectUnauthorized = false;
    const req = mod.request(url, options, (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.end();
  });
}

export class GatewayDiscovery {
  private _verifySsl: boolean;
  private _lastHealthy: boolean | null = null;
  private _logger: ModuleLogger;
  private _net: DnsResilientNet | null;

  constructor(opts?: { verifySsl?: boolean; logger?: ModuleLogger; net?: DnsResilientNet }) {
    this._verifySsl = opts?.verifySsl ?? true;
    this._logger = opts?.logger ?? _noopLogger;
    this._net = opts?.net ?? null;
  }

  /** 最近一次 health check 结果，null 表示尚未检查 */
  get lastHealthy(): boolean | null { return this._lastHealthy; }

  /**
   * 向 gatewayUrl 对应的 /health 端点发送 GET 请求，检查网关可用性。
   * 结果缓存到 lastHealthy，同时返回检查结果。
   */
  async checkHealth(gatewayUrl: string, timeout = 5_000): Promise<boolean> {
    const tStart = Date.now();
    const parsed = new URL(gatewayUrl);
    parsed.protocol = parsed.protocol === 'wss:' ? 'https:' : 'http:';
    parsed.pathname = '/health';
    parsed.search = '';
    parsed.hash = '';
    const healthUrl = parsed.toString();
    this._logger.debug(`checkHealth enter: url=${healthUrl}`);
    try {
      if (this._net) {
        this._lastHealthy = await this._net.httpGetOk(healthUrl, timeout);
      } else {
        this._lastHealthy = await _httpGetOk(healthUrl, this._verifySsl, timeout);
      }
      if (this._lastHealthy) {
        this._logger.debug(`checkHealth exit: elapsed=${Date.now() - tStart}ms healthy=true url=${healthUrl}`);
      } else {
        this._logger.warn(`health check failed: url=${healthUrl}`);
        this._logger.debug(`checkHealth exit: elapsed=${Date.now() - tStart}ms healthy=false url=${healthUrl}`);
      }
      return this._lastHealthy;
    } catch (err) {
      this._logger.debug(`checkHealth exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw err;
    }
  }

  /**
   * 从 well-known URL 发现 Gateway。
   *
   * @param wellKnownUrl - well-known 发现端点（如 https://alice.aid.com/.well-known/aun-gateway）
   * @param timeout - 请求超时（毫秒，默认 5000）
   * @returns Gateway WebSocket URL
   */
  async discover(wellKnownUrl: string, timeout = 5_000): Promise<string> {
    const urls = await this.discoverAll(wellKnownUrl, timeout);
    return urls[0];
  }

  async discoverAll(wellKnownUrl: string, timeout = 5_000): Promise<string[]> {
    const tStart = Date.now();
    this._logger.debug(`discoverAll enter: url=${wellKnownUrl}`);
    let payload: GatewayDiscoveryDocument;
    try {
      let rawPayload: unknown = null;
      const maxAttempts = _DISCOVERY_RETRY_DELAYS_MS.length + 1;
      for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
        try {
          if (this._net) {
            rawPayload = await this._net.httpGetJson(wellKnownUrl, timeout) as unknown;
          } else {
            rawPayload = await _httpGetJson(wellKnownUrl, this._verifySsl, timeout) as unknown;
          }
          break;
        } catch (err) {
          const isLastAttempt = attempt >= maxAttempts - 1;
          if (isLastAttempt || !_isTransientDiscoveryError(err)) {
            throw err;
          }
          this._logger.warn(
            `gateway discover transient failure, retrying: url=${wellKnownUrl}, attempt=${attempt + 1}/${maxAttempts}, error=${_errorMessage(err)}`,
          );
          await _sleep(_DISCOVERY_RETRY_DELAYS_MS[attempt]);
        }
      }
      if (!isJsonObject(rawPayload as JsonValue)) {
        throw new ValidationError('well-known returned invalid payload');
      }
      payload = rawPayload as GatewayDiscoveryDocument;
    } catch (err) {
      this._logger.error(`gateway discover failed: url=${wellKnownUrl}, error=${err instanceof Error ? err.message : String(err)}`);
      this._logger.debug(`discoverAll exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      throw new ConnectionError(
        `gateway discovery failed for ${wellKnownUrl}: ${err instanceof Error ? err.message : String(err)}`,
        { retryable: true },
      );
    }

    const gateways = payload.gateways;
    if (!Array.isArray(gateways) || gateways.length === 0) {
      this._logger.error(`gateway discover returned empty list: url=${wellKnownUrl}`);
      this._logger.debug(`discoverAll exit (error): elapsed=${Date.now() - tStart}ms err=empty_gateways`);
      throw new ValidationError('well-known returned empty gateways');
    }

    const sorted = [...gateways].sort(
      (a: GatewayEntry, b: GatewayEntry) => (Number(a.priority ?? 999)) - (Number(b.priority ?? 999)),
    );

    const urls = sorted.map(g => g.url).filter((u): u is string => typeof u === 'string' && u.length > 0);
    if (urls.length === 0) {
      this._logger.error(`gateway discover missing url field: wellKnown=${wellKnownUrl}`);
      this._logger.debug(`discoverAll exit (error): elapsed=${Date.now() - tStart}ms err=missing_url`);
      throw new ValidationError('well-known missing gateway url');
    }

    this._logger.debug(`discoverAll exit: elapsed=${Date.now() - tStart}ms gateways=${JSON.stringify(urls)}`);

    this.checkHealth(urls[0], timeout).catch(() => {});

    return urls;
  }
}
