import { describe, expect, it, vi } from 'vitest';

import {
  EmbeddedServiceRegistry,
  EndpointPolicy,
  ServiceProxyClient,
  type WebSocketFactoryOptions,
  type WebSocketLike,
} from '../../src/service-proxy.js';
import { AuthError, ValidationError } from '../../src/errors.js';

type Listener = (event: Event | MessageEvent | CloseEvent) => void;

class FakeWebSocket implements WebSocketLike {
  readonly protocol = '';
  readyState = 1;
  binaryType: BinaryType = 'arraybuffer';
  readonly sent: Array<Record<string, unknown>> = [];
  private readonly listeners = new Map<string, Set<Listener>>();

  constructor() {
    setTimeout(() => this.emit('open', new Event('open')), 0);
  }

  send(data: string | ArrayBuffer | Blob | ArrayBufferView): void {
    const text = typeof data === 'string' ? data : String(data);
    const message = JSON.parse(text) as Record<string, unknown>;
    this.sent.push(message);
    if (message.type === 'service_proxy_auth') {
      this.emitMessage({ type: 'service_proxy_auth_response', request_id: message.request_id, ok: true });
    } else if (message.type === 'register_services') {
      this.emitMessage({ type: 'register_services_ack', request_id: message.request_id, ok: true, count: 1 });
    } else if (message.type === 'heartbeat') {
      this.emitMessage({ type: 'heartbeat_ack', request_id: message.request_id, ok: true });
    }
  }

  close(code?: number, reason?: string): void {
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

  private emitMessage(payload: Record<string, unknown>): void {
    this.emit('message', new MessageEvent('message', { data: JSON.stringify(payload) }));
  }

  private emit(type: string, event: Event | MessageEvent | CloseEvent): void {
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }
}

describe('ServiceProxy registry', () => {
  it('注册服务摘要不暴露 endpoint，并递归清理敏感 metadata', () => {
    const registry = new EmbeddedServiceRegistry();

    registry.register('fileshare', 'http://127.0.0.1:8080/root', {
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

describe('ServiceProxyClient browser tunnel', () => {
  it('默认浏览器 WebSocket 无法携带 Authorization header 时抛出清晰 AuthError', async () => {
    const client = new ServiceProxyClient({
      providerAid: 'alice.agentid.pub',
      aunClient: {
        authenticate: vi.fn(async () => ({ access_token: 'fresh-token', expires_at: Date.now() / 1000 + 3600 })),
      },
    });
    (client as unknown as { discoverProxyWsUrl: () => Promise<string> }).discoverProxyWsUrl = async () => 'wss://proxy.agentid.pub/ws/client';

    await expect(client.connectOnce()).rejects.toThrow(AuthError);
    await expect(client.connectOnce()).rejects.toThrow(/webSocketFactory/i);
  });

  it('注入 webSocketFactory 后按协议发送认证、注册和 heartbeat 消息', async () => {
    const sockets: FakeWebSocket[] = [];
    let capturedOptions: WebSocketFactoryOptions | undefined;
    const factory = vi.fn((url: string, _protocols?: string | string[], options?: WebSocketFactoryOptions): WebSocketLike => {
      expect(url).toBe('wss://proxy.agentid.pub/ws/client');
      capturedOptions = options;
      const ws = new FakeWebSocket();
      sockets.push(ws);
      return ws;
    });
    const client = new ServiceProxyClient({
      providerAid: 'alice.agentid.pub',
      aunClient: {
        authenticate: vi.fn(async () => ({ access_token: 'fresh-token', expires_at: Date.now() / 1000 + 3600 })),
      },
      webSocketFactory: factory,
    });
    client.registerService('fileshare', 'http://127.0.0.1:8080/root');
    (client as unknown as { discoverProxyWsUrl: () => Promise<string> }).discoverProxyWsUrl = async () => 'wss://proxy.agentid.pub/ws/client';

    await expect(client.connectOnce({ heartbeatRequestId: 'hb' })).resolves.toEqual({ registered: 1, heartbeat: true });

    expect(capturedOptions?.headers?.Authorization).toBe('Bearer fresh-token');
    expect(sockets[0]?.sent.map((message) => message.type)).toEqual(['service_proxy_auth', 'register_services', 'heartbeat']);
    expect(sockets[0]?.sent[0]).toMatchObject({ provider_aid: 'alice.agentid.pub', client_version: 'js' });
  });
});
