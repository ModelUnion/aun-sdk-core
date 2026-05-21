// ── 长短连接共存单元测试 ──────────────────────────────────────
// 对标 Python tests/unit/test_connection_kind.py 的 10 个用例
import 'fake-indexeddb/auto';
import { describe, it, expect, vi } from 'vitest';
import { AUNClient } from '../../src/client.js';

describe('connection_kind 长短连接', () => {
  // 1. _NO_RECONNECT_CODES 包含 4012/4013
  it('_NO_RECONNECT_CODES 包含 4012 和 4013', () => {
    const codes = (AUNClient as any)._NO_RECONNECT_CODES as Set<number>;
    expect(codes.has(4012)).toBe(true);
    expect(codes.has(4013)).toBe(true);
  });

  // 2. _normalizeConnectParams 不传 connection_kind 默认 "long"
  it('_normalizeConnectParams 默认 connection_kind 为 long', () => {
    const client = new AUNClient();
    const params = (client as any)._normalizeConnectParams({
      access_token: 'tok',
      gateway: 'ws://localhost/aun',
    });
    expect(params.connection_kind).toBe('long');
    expect(params.short_ttl_ms).toBe(0);
  });

  // 3. _normalizeConnectParams 接受 kind="short" + short_ttl_ms
  it('_normalizeConnectParams 接受 kind=short + short_ttl_ms', () => {
    const client = new AUNClient();
    const params = (client as any)._normalizeConnectParams({
      access_token: 'tok',
      gateway: 'ws://localhost/aun',
      connection_kind: 'short',
      short_ttl_ms: 30000,
    });
    expect(params.connection_kind).toBe('short');
    expect(params.short_ttl_ms).toBe(30000);
  });

  // 4. _normalizeConnectParams 拒绝无效 kind
  it('_normalizeConnectParams 拒绝无效 connection_kind', () => {
    const client = new AUNClient();
    expect(() => {
      (client as any)._normalizeConnectParams({
        access_token: 'tok',
        gateway: 'ws://localhost/aun',
        connection_kind: 'invalid',
      });
    }).toThrow("connection_kind must be 'long' or 'short'");
  });

  // 5. _initializeSession kind=short 时 payload 含 options.kind="short" + short_ttl_ms
  it('auth.connect payload kind=short 含 options', async () => {
    const client = new AUNClient();
    const mockTransport = { call: vi.fn().mockResolvedValue({ status: 'ok' }) };

    // 直接调用 _initializeSession 绕过 challenge 校验
    const auth = (client as any)._auth;
    await (auth as any)._initializeSession(mockTransport, 'nonce123', 'mytoken', {
      deviceId: 'dev1',
      slotId: '',
      deliveryMode: { mode: 'fanout' },
      connectionKind: 'short',
      shortTtlMs: 15000,
    });

    expect(mockTransport.call).toHaveBeenCalledWith('auth.connect', expect.objectContaining({
      options: expect.objectContaining({
        kind: 'short',
        short_ttl_ms: 15000,
      }),
    }));
  });

  // 6. auth.connect payload kind=long 不含 options（向后兼容）
  it('auth.connect payload kind=long 不含 options', async () => {
    const client = new AUNClient();
    const mockTransport = { call: vi.fn().mockResolvedValue({ status: 'ok' }) };

    const auth = (client as any)._auth;
    await (auth as any)._initializeSession(mockTransport, 'nonce123', 'mytoken', {
      deviceId: 'dev1',
      slotId: '',
      deliveryMode: { mode: 'fanout' },
      connectionKind: 'long',
      shortTtlMs: 0,
    });

    const callArgs = mockTransport.call.mock.calls[0][1] as Record<string, any>;
    expect(callArgs.options).toBeUndefined();
  });

  // 7. 短连接禁用 heartbeat 与 token_refresh（短连接生命周期短，不需要长期会话维护）
  it('短连接禁用 heartbeat 与 token_refresh', () => {
    const client = new AUNClient();
    // 模拟 sessionOptions 为 short
    (client as any)._sessionOptions = { connection_kind: 'short' };
    const startHeartbeat = vi.spyOn(client as any, '_startHeartbeat').mockImplementation(() => {});
    const startTokenRefresh = vi.spyOn(client as any, '_startTokenRefresh').mockImplementation(() => {});

    (client as any)._startBackgroundTasks();

    expect(startHeartbeat).not.toHaveBeenCalled();
    expect(startTokenRefresh).not.toHaveBeenCalled();
    startHeartbeat.mockRestore();
    startTokenRefresh.mockRestore();
  });

  // 8. 长连接启动心跳和 token_refresh
  it('长连接启动心跳和 token_refresh', () => {
    const client = new AUNClient();
    (client as any)._sessionOptions = { connection_kind: 'long', heartbeat_interval: 30 };
    (client as any)._transport = { call: vi.fn().mockResolvedValue({}) };
    const startHeartbeat = vi.spyOn(client as any, '_startHeartbeat').mockImplementation(() => {});
    const startTokenRefresh = vi.spyOn(client as any, '_startTokenRefresh').mockImplementation(() => {});

    (client as any)._startBackgroundTasks();

    expect(startHeartbeat).toHaveBeenCalled();
    expect(startTokenRefresh).toHaveBeenCalled();
    expect((client as any)._startPrekeyRefresh).toBeUndefined();
    expect((client as any)._startGroupEpochTasks).toBeUndefined();
    startHeartbeat.mockRestore();
    startTokenRefresh.mockRestore();
  });

  // 9. 短连接不改变 auto_reconnect 默认值
  it('短连接 auto_reconnect 保持默认 true', () => {
    const client = new AUNClient();
    const opts = (client as any)._buildSessionOptions({
      connection_kind: 'short',
      short_ttl_ms: 10000,
    });
    expect(opts.auto_reconnect).toBe(true);
  });

  // 10. 长连接保持默认 auto_reconnect=true
  it('长连接保持默认 auto_reconnect=true', () => {
    const client = new AUNClient();
    const opts = (client as any)._buildSessionOptions({
      connection_kind: 'long',
      short_ttl_ms: 0,
    });
    expect(opts.auto_reconnect).toBe(true);
  });
});
