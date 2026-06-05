/**
 * Service Proxy provider 侧本地集成测试。
 *
 * 不依赖真实 Gateway / service_proxy 服务；测试内启动一个最小 fake proxy tunnel，
 * 驱动 ServiceProxyClient.serveOnce 跑 HTTP、SSE/File 流式响应和 WebSocket 桥接。
 */

import { once } from 'node:events';
import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import WebSocket, { WebSocketServer } from 'ws';

import { ServiceProxyClient } from '../../src/service-proxy.js';

const TEST_TIMEOUT = 20_000;

type Dict = Record<string, unknown>;

class FakeProxyTunnel {
  readonly server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  readonly received: Dict[] = [];
  private ws: WebSocket | null = null;
  private waiters: Array<{ predicate: (message: Dict) => boolean; resolve: (message: Dict) => void }> = [];

  async start(): Promise<string> {
    await once(this.server, 'listening');
    this.server.on('connection', (ws, request) => {
      expect(String(request.headers.authorization ?? '')).toBe('Bearer fresh-token');
      this.ws = ws;
      ws.on('message', (raw) => {
        const message = JSON.parse(raw.toString()) as Dict;
        this.received.push(message);
        this.resolveWaiters(message);
        if (message.type === 'service_proxy_auth') {
          ws.send(JSON.stringify({ type: 'service_proxy_auth_response', request_id: message.request_id, ok: true }));
          return;
        }
        if (message.type === 'register_services') {
          const services = Array.isArray(message.services) ? message.services : [];
          ws.send(JSON.stringify({ type: 'register_services_ack', request_id: message.request_id, ok: true, count: services.length }));
          return;
        }
      });
    });
    const address = this.server.address() as AddressInfo;
    return `ws://127.0.0.1:${address.port}/ws/client`;
  }

  send(message: Dict): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('fake proxy tunnel is not connected');
    }
    this.ws.send(JSON.stringify(message));
  }

  waitFor(predicate: (message: Dict) => boolean, timeoutMs = 3_000): Promise<Dict> {
    const existing = this.received.find(predicate);
    if (existing) return Promise.resolve(existing);
    return new Promise((resolve, reject) => {
      const waiter = { predicate, resolve };
      this.waiters.push(waiter);
      setTimeout(() => {
        this.waiters = this.waiters.filter(item => item !== waiter);
        reject(new Error(`waitFor fake proxy message timeout; received=${JSON.stringify(this.received)}`));
      }, timeoutMs);
    });
  }

  async close(): Promise<void> {
    try { this.ws?.close(); } catch { /* noop */ }
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  private resolveWaiters(message: Dict): void {
    const ready = this.waiters.filter(item => item.predicate(message));
    this.waiters = this.waiters.filter(item => !item.predicate(message));
    for (const waiter of ready) waiter.resolve(message);
  }
}

function startBackend(): Promise<{ baseHttp: string; baseWs: string; close: () => Promise<void> }> {
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
          spoof: req.headers['x-aun-spoof'] ?? '',
        }));
        return;
      }
      if (url.pathname === '/sse/live') {
        res.writeHead(200, { 'content-type': 'text/event-stream' });
        res.write('data: one\n\n');
        res.end('data: two\n\n');
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
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('missing');
    });
  });
  const wsServer = new WebSocketServer({ noServer: true });
  wsServer.on('connection', (ws) => {
    ws.on('message', (data, isBinary) => {
      if (isBinary) ws.send(Buffer.concat([Buffer.from('echo:'), Buffer.from(data as Buffer)]), { binary: true });
      else ws.send(`echo:${data.toString()}`);
    });
  });
  server.on('upgrade', (request, socket, head) => {
    wsServer.handleUpgrade(request, socket, head, ws => wsServer.emit('connection', ws, request));
  });

  return new Promise(resolve => {
    server.listen(0, '127.0.0.1', () => {
      const address = server.address() as AddressInfo;
      resolve({
        baseHttp: `http://127.0.0.1:${address.port}`,
        baseWs: `ws://127.0.0.1:${address.port}`,
        close: async () => {
          await new Promise<void>(done => wsServer.close(() => done()));
          await new Promise<void>(done => server.close(() => done()));
        },
      });
    });
  });
}

describe('ServiceProxyClient 本地隧道集成', () => {
  let tunnel: FakeProxyTunnel;
  let backend: Awaited<ReturnType<typeof startBackend>>;
  let client: ServiceProxyClient;
  let serveTask: Promise<Dict>;

  beforeEach(async () => {
    tunnel = new FakeProxyTunnel();
    const tunnelUrl = await tunnel.start();
    backend = await startBackend();
    client = new ServiceProxyClient({
      providerAid: 'alice.agentid.pub',
      aunClient: {
        authenticate: async () => ({ access_token: 'fresh-token', expires_at: Date.now() / 1000 + 3600 }),
      },
    });
    client.registerService('rest', `${backend.baseHttp}/http`, { visibility: 'public' });
    client.registerService('events', `${backend.baseHttp}/sse`, { serviceType: 'sse', visibility: 'public' });
    client.registerService('files', `${backend.baseHttp}/files`, { serviceType: 'file', visibility: 'public' });
    client.registerService('chat', `${backend.baseWs}/ws`, { serviceType: 'websocket', visibility: 'public' });
    (client as unknown as { discoverProxyWsUrl: () => Promise<string> }).discoverProxyWsUrl = async () => tunnelUrl;
    serveTask = client.serveOnce({ maxRequests: 4 });
    await tunnel.waitFor(message => message.type === 'register_services');
  });

  afterEach(async () => {
    client.stop();
    await Promise.allSettled([serveTask]);
    await tunnel.close();
    await backend.close();
  });

  it('转发 HTTP、流式响应和 WebSocket 后端', async () => {
    const requestID = 'req-http';
    tunnel.send({
      type: 'service_proxy_request',
      request_id: requestID,
      service_name: 'rest',
      method: 'POST',
      path: '/headers',
      query_string: 'x=1',
      headers: {
        'x-trace-id': 'trace-1',
        'x-aun-provider-aid': 'alice.agentid.pub',
        'x-aun-service-name': 'rest',
      },
      body_base64: Buffer.from('payload').toString('base64'),
    });
    const httpResponse = await tunnel.waitFor(message => message.type === 'service_proxy_response' && message.request_id === requestID);
    expect(httpResponse.status).toBe(202);
    const body = JSON.parse(Buffer.from(String(httpResponse.body_base64), 'base64').toString('utf8')) as Dict;
    expect(body).toMatchObject({
      method: 'POST',
      path: '/http/headers',
      query: '1',
      body: 'payload',
      provider: 'alice.agentid.pub',
      service: 'rest',
      trace: 'trace-1',
      spoof: '',
    });

    tunnel.send({
      type: 'service_proxy_request',
      request_id: 'req-sse',
      service_name: 'events',
      method: 'GET',
      path: '/live',
      headers: { accept: 'text/event-stream' },
    });
    const sse = await tunnel.waitFor(message => message.type === 'service_proxy_stream' && message.request_id === 'req-sse' && message.done === true);
    expect((sse.headers as Dict)['x-stream-type']).toBe('sse');
    expect(Buffer.from(String(sse.data_base64), 'base64').toString('utf8')).toBe('data: one\n\ndata: two\n\n');

    tunnel.send({
      type: 'service_proxy_request',
      request_id: 'req-file',
      service_name: 'files',
      method: 'GET',
      path: '/download/report.bin',
    });
    const file = await tunnel.waitFor(message => message.type === 'service_proxy_stream' && message.request_id === 'req-file' && message.done === true);
    expect((file.headers as Dict)['x-stream-type']).toBe('file');
    expect((file.headers as Dict)['content-disposition']).toBe('attachment; filename=report.bin');
    expect(Buffer.from(String(file.data_base64), 'base64').toString('utf8')).toBe('report-bytes');

    tunnel.send({
      type: 'ws_connect',
      connection_id: 'ws-1',
      service_name: 'chat',
      path: '/socket',
      subprotocols: ['chat.v1'],
    });
    const connected = await tunnel.waitFor(message => message.type === 'ws_connected' && message.connection_id === 'ws-1');
    expect(connected.subprotocol).toBe('chat.v1');
    tunnel.send({ type: 'ws_message', connection_id: 'ws-1', text: 'hello' });
    const wsText = await tunnel.waitFor(message => message.type === 'ws_message' && message.connection_id === 'ws-1' && message.text === 'echo:hello');
    expect(wsText.text).toBe('echo:hello');
    tunnel.send({ type: 'ws_message', connection_id: 'ws-1', data_base64: Buffer.from([1, 2]).toString('base64') });
    const wsBinary = await tunnel.waitFor(message => message.type === 'ws_message' && message.connection_id === 'ws-1' && typeof message.data_base64 === 'string');
    expect(Buffer.from(String(wsBinary.data_base64), 'base64')).toEqual(Buffer.from([101, 99, 104, 111, 58, 1, 2]));
    tunnel.send({ type: 'ws_close', connection_id: 'ws-1', code: 1000, reason: '' });

    await expect(serveTask).resolves.toEqual({ registered: 4, handled_requests: 4 });
  }, TEST_TIMEOUT);
});
