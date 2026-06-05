/**
 * Service Proxy 浏览器 SDK 集成测试。
 *
 * 这里不依赖真实 service_proxy 服务；通过注入 webSocketFactory 驱动 provider tunnel，
 * 覆盖浏览器 SDK 的 HTTP/SSE/File 转发路径。真实浏览器无法给 WebSocket 设置
 * Authorization header，因此真实网络 provider tunnel 边界在 e2e-browser 中单独覆盖。
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
  readonly options?: WebSocketFactoryOptions;
  private readonly listeners = new Map<string, Set<Listener>>();

  constructor(options?: WebSocketFactoryOptions) {
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
    const chunks: Buffer[] = [];
    req.on('data', chunk => chunks.push(Buffer.from(chunk)));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      if (url.pathname === '/http/headers') {
        res.writeHead(202, { 'content-type': 'application/json', 'x-backend': 'ok' });
        res.end(JSON.stringify({
          method: req.method,
          path: url.pathname,
          query: url.searchParams.get('x') ?? '',
          body: body.toString('utf8'),
          provider: req.headers['x-aun-provider-aid'] ?? '',
          service: req.headers['x-aun-service-name'] ?? '',
          trace: req.headers['x-trace-id'] ?? '',
        }));
        return;
      }
      if (url.pathname === '/sse/live') {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        res.end('data: one\n\ndata: two\n\n');
        return;
      }
      if (url.pathname === '/files/download/report.bin') {
        res.writeHead(200, {
          'content-type': 'application/octet-stream',
          'content-disposition': 'attachment; filename=report.bin',
        });
        res.end('report-bytes');
        return;
      }
      res.writeHead(404);
      res.end('missing');
    });
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as AddressInfo;
  return {
    baseHttp: `http://127.0.0.1:${address.port}`,
    close: async () => new Promise<void>(resolve => server.close(() => resolve())),
  };
}

describe('ServiceProxyClient 浏览器集成', () => {
  let backend: Awaited<ReturnType<typeof startBackend>>;
  let tunnel: ScriptedWebSocket | undefined;
  let client: ServiceProxyClient;
  let serveTask: Promise<Dict>;

  beforeEach(async () => {
    backend = await startBackend();
    const factory = (url: string, _protocols?: string | string[], options?: WebSocketFactoryOptions): WebSocketLike => {
      expect(url).toBe('wss://proxy.agentid.pub/ws/client');
      tunnel = new ScriptedWebSocket(options);
      return tunnel;
    };
    client = new ServiceProxyClient({
      providerAid: 'alice.agentid.pub',
      aunClient: {
        authenticate: async () => ({ access_token: 'fresh-token', expires_at: Date.now() / 1000 + 3600 }),
      },
      webSocketFactory: factory,
    });
    client.registerService('rest', `${backend.baseHttp}/http`, { visibility: 'public' });
    client.registerService('events', `${backend.baseHttp}/sse`, { serviceType: 'sse', visibility: 'public' });
    client.registerService('files', `${backend.baseHttp}/files`, { serviceType: 'file', visibility: 'public' });
    (client as unknown as { discoverProxyWsUrl: () => Promise<string> }).discoverProxyWsUrl = async () => 'wss://proxy.agentid.pub/ws/client';
    serveTask = client.serveOnce({ maxRequests: 3 });
    const activeTunnel = await waitForTunnel(() => tunnel);
    await activeTunnel.waitFor(message => message.type === 'register_services');
  });

  afterEach(async () => {
    client.stop();
    await Promise.allSettled([serveTask]);
    await backend.close();
  });

  it('注入 webSocketFactory 后可转发 HTTP、SSE 和文件响应', async () => {
    const activeTunnel = await waitForTunnel(() => tunnel);
    expect(activeTunnel.options?.headers?.Authorization).toBe('Bearer fresh-token');

    activeTunnel.serverSend({
      type: 'service_proxy_request',
      request_id: 'req-http',
      service_name: 'rest',
      method: 'POST',
      path: '/headers',
      query_string: 'x=1',
      headers: {
        'x-trace-id': 'trace-js',
        'x-aun-provider-aid': 'alice.agentid.pub',
        'x-aun-service-name': 'rest',
      },
      body_base64: btoa('payload'),
    });
    const httpResponse = await activeTunnel.waitFor(message => message.type === 'service_proxy_response' && message.request_id === 'req-http');
    expect(httpResponse.status).toBe(202);
    expect(JSON.parse(atob(String(httpResponse.body_base64)))).toMatchObject({
      method: 'POST',
      path: '/http/headers',
      query: '1',
      body: 'payload',
      provider: 'alice.agentid.pub',
      service: 'rest',
      trace: 'trace-js',
    });

    activeTunnel.serverSend({ type: 'service_proxy_request', request_id: 'req-sse', service_name: 'events', method: 'GET', path: '/live' });
    const sse = await activeTunnel.waitFor(message => message.type === 'service_proxy_stream' && message.request_id === 'req-sse' && message.done === true);
    expect((sse.headers as Dict)['x-stream-type']).toBe('sse');
    expect(atob(String(sse.data_base64))).toBe('data: one\n\ndata: two\n\n');

    activeTunnel.serverSend({ type: 'service_proxy_request', request_id: 'req-file', service_name: 'files', method: 'GET', path: '/download/report.bin' });
    const file = await activeTunnel.waitFor(message => message.type === 'service_proxy_stream' && message.request_id === 'req-file' && message.done === true);
    expect((file.headers as Dict)['x-stream-type']).toBe('file');
    expect(atob(String(file.data_base64))).toBe('report-bytes');

    await expect(serveTask).resolves.toEqual({ registered: 3, handled_requests: 3 });
  }, 20_000);
});

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
