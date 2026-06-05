/**
 * Service Proxy 浏览器 SDK 双域边界集成测试。
 *
 * 浏览器原生 WebSocket 不能携带 Authorization header，因此这里通过注入
 * webSocketFactory 覆盖 JS SDK provider 侧的 issuer 选择与本域隧道转发边界。
 */

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';

import { ServiceProxyClient, type WebSocketFactoryOptions, type WebSocketLike } from '../../src/service-proxy.js';

type Dict = Record<string, unknown>;
type Listener = (event: Event | MessageEvent | CloseEvent) => void;

class ScriptedWebSocket implements WebSocketLike {
  readonly protocol = '';
  readyState = 0;
  binaryType: BinaryType = 'arraybuffer';
  readonly clientMessages: Dict[] = [];
  readonly url: string;
  readonly options?: WebSocketFactoryOptions;
  private readonly listeners = new Map<string, Set<Listener>>();

  constructor(url: string, options?: WebSocketFactoryOptions) {
    this.url = url;
    this.options = options;
    setTimeout(() => {
      this.readyState = 1;
      this.emit('open', new Event('open'));
    }, 0);
  }

  send(data: string | ArrayBuffer | Blob | ArrayBufferView): void {
    if (typeof data !== 'string') throw new Error('fake tunnel only accepts text frames');
    const message = JSON.parse(data) as Dict;
    this.clientMessages.push(message);
    if (message.type === 'service_proxy_auth') {
      this.serverSend({ type: 'service_proxy_auth_response', request_id: message.request_id, ok: true });
    } else if (message.type === 'register_services') {
      const services = Array.isArray(message.services) ? message.services : [];
      this.serverSend({ type: 'register_services_ack', request_id: message.request_id, ok: true, count: services.length });
    }
  }

  close(code?: number, reason?: string): void {
    this.readyState = 3;
    const event = typeof CloseEvent === 'function'
      ? new CloseEvent('close', { code: code ?? 1000, reason: reason ?? '' })
      : new Event('close') as CloseEvent;
    this.emit('close', event);
  }

  addEventListener(type: 'open' | 'message' | 'close' | 'error', listener: Listener): void {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type)!.add(listener);
  }

  removeEventListener(type: 'open' | 'message' | 'close' | 'error', listener: Listener): void {
    this.listeners.get(type)?.delete(listener);
  }

  serverSend(payload: Dict): void {
    this.emit('message', new MessageEvent('message', { data: JSON.stringify(payload) }));
  }

  waitFor(predicate: (message: Dict) => boolean, timeoutMs = 3_000): Promise<Dict> {
    const existing = this.clientMessages.find(predicate);
    if (existing) return Promise.resolve(existing);
    return new Promise((resolve, reject) => {
      const deadline = Date.now() + timeoutMs;
      const timer = setInterval(() => {
        const found = this.clientMessages.find(predicate);
        if (found) {
          clearInterval(timer);
          resolve(found);
          return;
        }
        if (Date.now() > deadline) {
          clearInterval(timer);
          reject(new Error(`等待 fake tunnel 消息超时: ${JSON.stringify(this.clientMessages)}`));
        }
      }, 20);
    });
  }

  private emit(type: string, event: Event | MessageEvent | CloseEvent): void {
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }
}

async function startBackend(): Promise<{ baseHttp: string; close: () => Promise<void> }> {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end(`${req.method}:${url.pathname}:${req.headers['x-aun-provider-aid'] ?? ''}`);
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as AddressInfo;
  return {
    baseHttp: `http://127.0.0.1:${address.port}`,
    close: async () => new Promise<void>(resolve => server.close(() => resolve())),
  };
}

function waitForTunnel(getter: () => ScriptedWebSocket | undefined, timeoutMs = 3_000): Promise<ScriptedWebSocket> {
  const existing = getter();
  if (existing) return Promise.resolve(existing);
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeoutMs;
    const timer = setInterval(() => {
      const tunnel = getter();
      if (tunnel) {
        clearInterval(timer);
        resolve(tunnel);
        return;
      }
      if (Date.now() > deadline) {
        clearInterval(timer);
        reject(new Error('等待 fake tunnel 创建超时'));
      }
    }, 20);
  });
}

describe('ServiceProxyClient 浏览器双域边界集成', () => {
  let backend: Awaited<ReturnType<typeof startBackend>>;
  let client: ServiceProxyClient;
  let serveTask: Promise<Dict>;
  let localTunnel: ScriptedWebSocket | undefined;
  const createdUrls: string[] = [];

  beforeEach(async () => {
    backend = await startBackend();
    createdUrls.length = 0;
    localTunnel = undefined;
    const factory = (url: string, _protocols?: string | string[], options?: WebSocketFactoryOptions): WebSocketLike => {
      createdUrls.push(url);
      const socket = new ScriptedWebSocket(url, options);
      if (url.includes('proxy.aid.com')) localTunnel = socket;
      return socket;
    };
    client = new ServiceProxyClient({
      providerAid: 'js-sp-fed.aid.com',
      aunClient: {
        authenticate: async () => ({ access_token: 'fresh-token', expires_at: Date.now() / 1000 + 3600 }),
      },
      webSocketFactory: factory,
    });
    client.registerService('fileshare', `${backend.baseHttp}/http`, { visibility: 'public' });
    (client as unknown as { discoverProxyWsUrl: () => Promise<string> }).discoverProxyWsUrl = async () => 'wss://proxy.aid.com/ws/client';
    serveTask = client.serveOnce({ maxRequests: 1 });
    const tunnel = await waitForTunnel(() => localTunnel);
    await tunnel.waitFor(message => message.type === 'register_services');
  });

  afterEach(async () => {
    client.stop();
    await Promise.allSettled([serveTask]);
    await backend.close();
  });

  it('provider 只连接本域 proxy，并通过本域隧道完成转发', async () => {
    const tunnel = await waitForTunnel(() => localTunnel);
    expect(createdUrls).toEqual(['wss://proxy.aid.com/ws/client']);
    expect(createdUrls.some(url => url.includes('proxy.aid.net'))).toBe(false);
    expect(tunnel.options?.headers?.Authorization).toBe('Bearer fresh-token');

    const register = await tunnel.waitFor(message => message.type === 'register_services');
    expect(register.services).toEqual([
      {
        service_name: 'fileshare',
        service_type: 'http',
        visibility: 'public',
        metadata: {},
      },
    ]);

    tunnel.serverSend({
      type: 'service_proxy_request',
      request_id: 'req-local',
      service_name: 'fileshare',
      method: 'GET',
      path: '/probe',
      headers: {
        'x-aun-provider-aid': 'js-sp-fed.aid.com',
        'x-aun-service-name': 'fileshare',
      },
    });
    const response = await tunnel.waitFor(message => message.type === 'service_proxy_response' && message.request_id === 'req-local');
    expect(response.status).toBe(200);
    expect(atob(String(response.body_base64))).toBe('GET:/http/probe:js-sp-fed.aid.com');

    await expect(serveTask).resolves.toEqual({ registered: 1, handled_requests: 1 });
  }, 20_000);
});
