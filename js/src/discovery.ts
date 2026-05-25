// ── Gateway 发现（浏览器 fetch API）──────────────────────

import { ConnectionError, ValidationError } from './errors.js';
import type { ModuleLogger } from './logger.js';
import { isJsonObject, type GatewayDiscoveryDocument, type GatewayEntry, type JsonValue } from './types.js';

const _noopLog: ModuleLogger = { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} };

/**
 * Gateway 发现服务 — 通过 .well-known 端点发现 Gateway WebSocket URL。
 *
 * 使用浏览器 fetch() API，不依赖任何 Node.js 模块。
 */
export class GatewayDiscovery {
  private _log: ModuleLogger = _noopLog;
  setLogger(log: ModuleLogger): void { this._log = log; }

  private _lastHealthy: boolean | null = null;

  /** 最近一次 health check 结果，null 表示尚未检查 */
  get lastHealthy(): boolean | null { return this._lastHealthy; }

  /** 向 gatewayUrl 对应的 /health 端点发送 GET 请求，检查网关可用性。 */
  async checkHealth(gatewayUrl: string, timeout = 5000): Promise<boolean> {
    const tStart = Date.now();
    const parsed = new URL(gatewayUrl);
    parsed.protocol = parsed.protocol === 'wss:' ? 'https:' : 'http:';
    parsed.pathname = '/health';
    parsed.search = '';
    parsed.hash = '';
    const healthUrl = parsed.toString();
    this._log.debug(`checkHealth enter: url=${healthUrl}`);
    try {
      const controller = new AbortController();
      const timer = globalThis.setTimeout(() => controller.abort(), timeout);
      const resp = await fetch(healthUrl, { method: 'GET', signal: controller.signal });
      clearTimeout(timer);
      this._lastHealthy = resp.status === 200;
    } catch (err) {
      this._lastHealthy = false;
      this._log.debug(`checkHealth exit (error): elapsed=${Date.now() - tStart}ms err=${err instanceof Error ? err.message : String(err)}`);
      return this._lastHealthy;
    }
    this._log.debug(`checkHealth exit: elapsed=${Date.now() - tStart}ms healthy=${this._lastHealthy}`);
    return this._lastHealthy;
  }

  /**
   * 从 well-known URL 发现 Gateway WebSocket 地址。
   *
   * 响应格式: { gateways: [{ url: "wss://...", priority: 1 }, ...] }
   * 选择 priority 最小的网关。
   */
  async discover(wellKnownUrl: string, timeout = 5000): Promise<string> {
    const urls = await this.discoverAll(wellKnownUrl, timeout);
    return urls[0];
  }

  /**
   * 从 well-known URL 发现所有 Gateway WebSocket 地址（按 priority 排序）。
   */
  async discoverAll(wellKnownUrl: string, timeout = 5000): Promise<string[]> {
    const tStart = Date.now();
    this._log.debug(`discoverAll enter: url=${wellKnownUrl}`);
    let payload: GatewayDiscoveryDocument;
    try {
      const controller = new AbortController();
      const timer = globalThis.setTimeout(() => controller.abort(), timeout);

      const response = await fetch(wellKnownUrl, {
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      const rawPayload = await response.json() as JsonValue;
      if (!isJsonObject(rawPayload)) {
        throw new ValidationError('well-known returned invalid payload');
      }
      payload = rawPayload as GatewayDiscoveryDocument;
    } catch (exc) {
      this._log.debug(`discoverAll exit (error): elapsed=${Date.now() - tStart}ms err=${exc instanceof Error ? exc.message : String(exc)}`);
      throw new ConnectionError(
        `gateway discovery failed for ${wellKnownUrl}: ${exc}`,
        { retryable: true },
      );
    }

    const gateways = payload.gateways;
    if (!Array.isArray(gateways) || gateways.length === 0) {
      this._log.debug(`discoverAll exit (error): elapsed=${Date.now() - tStart}ms err=empty_gateways`);
      throw new ValidationError('well-known returned empty gateways');
    }

    const sorted = [...gateways].sort(
      (a: GatewayEntry, b: GatewayEntry) =>
        (Number(a.priority ?? 999)) - (Number(b.priority ?? 999)),
    );

    const urls = sorted.map(g => String(g.url ?? '')).filter(u => u.length > 0);
    if (urls.length === 0) {
      this._log.debug(`discoverAll exit (error): elapsed=${Date.now() - tStart}ms err=missing_url`);
      throw new ValidationError('well-known missing gateway url');
    }

    this.checkHealth(urls[0], timeout).catch(() => {});

    this._log.debug(`discoverAll exit: elapsed=${Date.now() - tStart}ms gateways=${JSON.stringify(urls)}`);
    return urls;
  }
}
