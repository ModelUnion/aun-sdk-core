import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import { describe, expect, it, vi } from 'vitest';
import { WebSocketServer } from 'ws';

import { EmbeddedServiceRegistry, EndpointPolicy, ServiceProxyClient } from '../../src/service-proxy.js';
import { ValidationError } from '../../src/errors.js';

async function closeServer(server: WebSocketServer): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
  });
}

describe('ServiceProxy registry', () => {
  it('注册服务摘要不暴露 endpoint，并递归清理敏感 metadata', () => {
    const registry = new EmbeddedServiceRegistry();

    const record = registry.register('fileshare', 'http://127.0.0.1:8080/root', {
      serviceType: 'http',
      visibility: 'public',
      metadata: {
        title: 'Files',
        endpoint: 'http://127.0.0.1:8080/root',
        token: 'SECRET',
        nested: { access_token: 'SECRET', label: 'ok' },
        items: [{ password: 'SECRET', name: 'one' }],
      },
    });

    expect(record.endpoint).toBe('http://127.0.0.1:8080/root');
    expect(registry.listSummaries()).toEqual([
      {
        service_name: 'fileshare',
        service_type: 'http',
        visibility: 'public',
        metadata: {
          title: 'Files',
          nested: { label: 'ok' },
          items: [{ name: 'one' }],
        },
      },
    ]);
  });

  it('默认 endpoint policy 只允许 localhost 和 IPv4 loopback', () => {
    const policy = new EndpointPolicy();

    expect(policy.isAllowed('http://127.0.0.1:8080')).toBe(true);
    expect(policy.isAllowed('wss://localhost:8765/ws')).toBe(true);
    expect(policy.isAllowed('http://[::1]:8080')).toBe(false);
    expect(policy.isAllowed('http://10.0.0.1:8080')).toBe(false);
    expect(policy.isAllowed('file:///tmp/service.sock')).toBe(false);
  });

  it('支持显式 allowlist 主机，并拒绝非法服务名', () => {
    const policy = new EndpointPolicy({ allowedHosts: ['service.internal'] });
    const registry = new EmbeddedServiceRegistry({ endpointPolicy: policy });

    expect(registry.register('fileshare', 'http://service.internal:8080').endpoint).toBe('http://service.internal:8080');
    expect(() => registry.register('api', 'http://127.0.0.1:8080')).toThrow(ValidationError);
    expect(() => registry.register('Upper', 'http://127.0.0.1:8080')).toThrow(ValidationError);
  });
});

describe('ServiceProxyClient Gateway 控制面', () => {
  it('通过 proxy.* 方法注册、注销和查询服务', async () => {
    const call = vi.fn(async () => ({ ok: true }));
    const client = new ServiceProxyClient({
      providerAid: 'alice.agentid.pub',
      aunClient: { call },
    });
    client.registerService('fileshare', 'http://127.0.0.1:8080/root', {
      visibility: 'public',
      metadata: { title: 'Files', endpoint: 'http://127.0.0.1:8080/root' },
    });

    await expect(client.registerServicesWithGateway()).resolves.toEqual({ ok: true });
    await client.unregisterServicesFromGateway('fileshare');
    await client.listGatewayServices();

    expect(call.mock.calls[0]).toEqual([
      'proxy.register_services',
      {
        provider_aid: 'alice.agentid.pub',
        services: [
          {
            service_name: 'fileshare',
            service_type: 'http',
            visibility: 'public',
            metadata: { title: 'Files' },
          },
        ],
      },
    ]);
    expect(call.mock.calls[1]).toEqual([
      'proxy.unregister_services',
      { provider_aid: 'alice.agentid.pub', service_names: ['fileshare'] },
    ]);
    expect(call.mock.calls[2]).toEqual([
      'proxy.list_services',
      { provider_aid: 'alice.agentid.pub' },
    ]);
  });
});

describe('ServiceProxyClient tunnel', () => {
  it('connectOnce 使用 AUN token 建立 tunnel，并按协议完成认证和注册', async () => {
    const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await once(server, 'listening');
    const address = server.address() as AddressInfo;
    const wsUrl = `ws://127.0.0.1:${address.port}/ws/client`;
    const messages: Array<Record<string, unknown>> = [];
    let authorization = '';

    server.on('connection', (ws, request) => {
      authorization = String(request.headers.authorization ?? '');
      ws.on('message', (raw) => {
        const message = JSON.parse(raw.toString()) as Record<string, unknown>;
        messages.push(message);
        if (message.type === 'service_proxy_auth') {
          ws.send(JSON.stringify({ type: 'service_proxy_auth_response', request_id: message.request_id, ok: true }));
        } else if (message.type === 'register_services') {
          ws.send(JSON.stringify({ type: 'register_services_ack', request_id: message.request_id, ok: true, count: 1 }));
        } else if (message.type === 'heartbeat') {
          ws.send(JSON.stringify({ type: 'heartbeat_ack', request_id: message.request_id, ok: true }));
        }
      });
    });

    const authenticate = vi.fn(async () => ({
      access_token: 'fresh-token',
      expires_at: Date.now() / 1000 + 3600,
    }));
    const client = new ServiceProxyClient({
      providerAid: 'alice.agentid.pub',
      aunClient: { authenticate },
    });
    client.registerService('fileshare', 'http://127.0.0.1:8080/root');
    (client as unknown as { discoverProxyWsUrl: () => Promise<string> }).discoverProxyWsUrl = async () => wsUrl;

    try {
      await expect(client.connectOnce({ heartbeatRequestId: 'hb' })).resolves.toEqual({ registered: 1, heartbeat: true });
      expect(authenticate).toHaveBeenCalledTimes(1);
      expect(authorization).toBe('Bearer fresh-token');
      expect(messages.map((message) => message.type)).toEqual(['service_proxy_auth', 'register_services', 'heartbeat']);
      expect(messages[0]).toMatchObject({ provider_aid: 'alice.agentid.pub', client_version: 'ts' });
    } finally {
      await closeServer(server);
    }
  });

  it('后端 WebSocket close 使用可发送 close code', async () => {
    const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
    await once(server, 'listening');
    const address = server.address() as AddressInfo;
    const wsUrl = `ws://127.0.0.1:${address.port}/root`;
    const serverClosed = new Promise<void>((resolve) => {
      server.on('connection', (ws) => {
        ws.on('close', () => resolve());
      });
    });
    const client = new ServiceProxyClient({ providerAid: 'alice.agentid.pub' });
    client.registerService('chat', wsUrl, { serviceType: 'websocket', visibility: 'public' });
    const sent: Array<Record<string, unknown>> = [];
    const tunnel = { send: vi.fn(async (payload: Record<string, unknown>) => { sent.push(payload); }) };
    let shifted = false;
    const inboundQueue = {
      async shift() {
        if (shifted) return null;
        shifted = true;
        return { type: 'ws_close', connection_id: 'ws-1', code: 1006, reason: 'abnormal' };
      },
    };

    try {
      await expect(client.handleWsConnectMessage(
        { type: 'ws_connect', connection_id: 'ws-1', service_name: 'chat', path: '/socket' },
        tunnel as any,
        inboundQueue as any,
      )).resolves.toBeUndefined();
      await expect(serverClosed).resolves.toBeUndefined();
      expect(sent[0]).toMatchObject({ type: 'ws_connected', connection_id: 'ws-1' });
    } finally {
      await closeServer(server);
    }
  });
});
