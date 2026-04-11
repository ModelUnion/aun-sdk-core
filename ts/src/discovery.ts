/**
 * Gateway 发现
 *
 * 通过 HTTPS GET 请求 well-known URL 获取 Gateway 列表，
 * 按优先级排序后返回最优 Gateway 的 WebSocket URL。
 *
 * 与 Python SDK 的 GatewayDiscovery 完全对齐。
 */

import * as http from 'node:http';
import * as https from 'node:https';
import { ConnectionError, ValidationError } from './errors.js';
import { isJsonObject, type GatewayDiscoveryDocument, type GatewayEntry, type JsonValue } from './types.js';

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

export class GatewayDiscovery {
  private _verifySsl: boolean;

  constructor(opts?: { verifySsl?: boolean }) {
    this._verifySsl = opts?.verifySsl ?? true;
  }

  /**
   * 从 well-known URL 发现 Gateway。
   *
   * @param wellKnownUrl - well-known 发现端点（如 https://alice.aid.com/.well-known/aun-gateway）
   * @param timeout - 请求超时（毫秒，默认 5000）
   * @returns Gateway WebSocket URL
   */
  async discover(wellKnownUrl: string, timeout = 5_000): Promise<string> {
    let payload: GatewayDiscoveryDocument;
    try {
      const rawPayload = await _httpGetJson(wellKnownUrl, this._verifySsl, timeout);
      if (!isJsonObject(rawPayload)) {
        throw new ValidationError('well-known returned invalid payload');
      }
      payload = rawPayload as GatewayDiscoveryDocument;
    } catch (err) {
      throw new ConnectionError(
        `gateway discovery failed for ${wellKnownUrl}: ${err instanceof Error ? err.message : String(err)}`,
        { retryable: true },
      );
    }

    const gateways = payload.gateways;
    if (!Array.isArray(gateways) || gateways.length === 0) {
      throw new ValidationError('well-known returned empty gateways');
    }

    // 按 priority 排序（数值越小优先级越高）
    const sorted = [...gateways].sort(
      (a: GatewayEntry, b: GatewayEntry) => (Number(a.priority ?? 999)) - (Number(b.priority ?? 999)),
    );

    const url = sorted[0]?.url;
    if (!url || typeof url !== 'string') {
      throw new ValidationError('well-known missing gateway url');
    }
    return url;
  }
}
