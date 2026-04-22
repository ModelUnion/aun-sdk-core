// ── Gateway 发现（浏览器 fetch API）──────────────────────

import { ConnectionError, ValidationError } from './errors.js';
import { isJsonObject, type GatewayDiscoveryDocument, type GatewayEntry, type JsonValue } from './types.js';

/**
 * Gateway 发现服务 — 通过 .well-known 端点发现 Gateway WebSocket URL。
 *
 * 使用浏览器 fetch() API，不依赖任何 Node.js 模块。
 */
export class GatewayDiscovery {
  private _lastHealthy: boolean | null = null;

  /** 最近一次 health check 结果，null 表示尚未检查 */
  get lastHealthy(): boolean | null { return this._lastHealthy; }

  /** 向 gatewayUrl 对应的 /health 端点发送 HEAD 请求，检查网关可用性。 */
  async checkHealth(gatewayUrl: string, timeout = 5000): Promise<boolean> {
    const healthUrl = gatewayUrl.replace(/^wss?:\/\//, (m) => m === 'wss://' ? 'https://' : 'http://')
      .replace(/\/?$/, '/health');
    try {
      const controller = new AbortController();
      const timer = globalThis.setTimeout(() => controller.abort(), timeout);
      const resp = await fetch(healthUrl, { method: 'HEAD', signal: controller.signal });
      clearTimeout(timer);
      this._lastHealthy = resp.status === 200;
    } catch {
      this._lastHealthy = false;
    }
    return this._lastHealthy;
  }

  /**
   * 从 well-known URL 发现 Gateway WebSocket 地址。
   *
   * 响应格式: { gateways: [{ url: "wss://...", priority: 1 }, ...] }
   * 选择 priority 最小的网关。
   */
  async discover(wellKnownUrl: string, timeout = 5000): Promise<string> {
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
      throw new ConnectionError(
        `gateway discovery failed for ${wellKnownUrl}: ${exc}`,
        { retryable: true },
      );
    }

    const gateways = payload.gateways;
    if (!Array.isArray(gateways) || gateways.length === 0) {
      throw new ValidationError('well-known returned empty gateways');
    }

    // 按 priority 排序（低优先级数字 = 高优先级）
    const sorted = [...gateways].sort(
      (a: GatewayEntry, b: GatewayEntry) =>
        (Number(a.priority ?? 999)) - (Number(b.priority ?? 999)),
    );

    const url = sorted[0]?.url;
    if (!url) {
      throw new ValidationError('well-known missing gateway url');
    }

    // 发现后异步触发 health check（不阻塞）
    this.checkHealth(String(url), timeout).catch(() => {});

    return String(url);
  }
}
