import { describe, expect, it, vi } from 'vitest';

import { ValidationError } from '../../src/errors.js';
import { LifecycleController } from '../../src/client/lifecycle.js';
import { ClientRuntime } from '../../src/client/runtime.js';
import { ConnectionState, STATE_TO_PUBLIC } from '../../src/types.js';

function createLifecycle(overrides: Record<string, unknown> = {}): { lifecycle: LifecycleController; client: Record<string, any> } {
  const client: Record<string, any> = {
    _state: 'standby',
    _aid: 'alice.agentid.pub',
    _currentAid: {
      aid: 'alice.agentid.pub',
      isPrivateKeyValid: () => true,
    },
    _gatewayUrl: null,
    _identity: null,
    _sessionParams: null,
    _retryAttempt: 3,
    _nextRetryAt: new Date(Date.now() + 1000),
    _lastError: new Error('stale'),
    _lastErrorCode: 'stale',
    _deviceId: 'device-a',
    _slotId: 'slot-a',
    get state() {
      return STATE_TO_PUBLIC[this._state] ?? this._state;
    },
    _clientLog: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
    _resolveGatewayForAid: vi.fn(async () => 'ws://discovered-gateway/aun'),
    _auth: {
      authenticate: vi.fn(async (gateway: string) => ({ access_token: 'tok-auth', gateway_url: gateway.replace('discovered', 'returned') })),
      loadIdentityOrNone: vi.fn(() => ({ aid: 'alice.agentid.pub', access_token: 'tok-loaded' })),
    },
    _stopReconnect: vi.fn(),
    _normalizeConnectParams: vi.fn((params: Record<string, any>) => ({
      ...params,
      connection_kind: params.connection_kind ?? 'long',
      short_ttl_ms: params.connection_kind === 'short' ? params.short_ttl_ms ?? 0 : 0,
      device_id: 'device-a',
      slot_id: 'slot-a',
    })),
    _captureCapabilitiesFromConnect: vi.fn(),
    _buildSessionOptions: vi.fn((params: Record<string, any>) => ({
      auto_reconnect: params.auto_reconnect ?? true,
      background_sync: params.background_sync ?? true,
      retry: params.retry ?? {},
      timeouts: { call: params.timeouts?.call ?? 35 },
      connection_kind: params.connection_kind ?? 'long',
    })),
    _transport: { setTimeout: vi.fn() },
    _resolveGateways: vi.fn((params: Record<string, any>) => [params.gateway]),
    _connectOnce: vi.fn(async () => {
      client._state = 'ready';
    }),
    ...overrides,
  };
  const lifecycle = new LifecycleController(new ClientRuntime(client));
  client.authenticate = vi.fn(async () => lifecycle.authenticate());
  return { lifecycle, client };
}

describe('LifecycleController 组件边界', () => {
  it('authenticate 拒绝外部 gateway/gateways，gateway 必须由 discovery 解析', async () => {
    const { lifecycle } = createLifecycle();

    await expect(lifecycle.authenticate({ gateway: 'ws://manual/aun' } as any)).rejects.toThrow(ValidationError);
    await expect(lifecycle.authenticate({ gateways: ['ws://manual/aun'] } as any)).rejects.toThrow(/gateway must be resolved by discovery/);
  });

  it('authenticate 使用当前 AID 自动发现 gateway，并兼容 auth 返回 gateway_url', async () => {
    const { lifecycle, client } = createLifecycle();

    const result = await lifecycle.authenticate();

    expect(result.access_token).toBe('tok-auth');
    expect(client._resolveGatewayForAid).toHaveBeenCalledWith('alice.agentid.pub');
    expect(client._auth.authenticate).toHaveBeenCalledWith('ws://discovered-gateway/aun', { aid: 'alice.agentid.pub' });
    expect(client._gatewayUrl).toBe('ws://returned-gateway/aun');
    expect(client._state).toBe('authenticated');
    expect(client._lastError).toBeNull();
    expect(client._lastErrorCode).toBeNull();
  });

  it('authenticate 成功后 identity reload 失败时使用认证结果回填内存 identity', async () => {
    const { lifecycle, client } = createLifecycle({
      _identity: { aid: 'alice.agentid.pub', private_key_pem: 'priv', public_key_der_b64: 'pub', cert: 'cert' },
      _auth: {
        authenticate: vi.fn(async (gateway: string) => ({
          access_token: 'tok-auth',
          refresh_token: 'refresh-auth',
          expires_at: 12345,
          gateway_url: gateway,
        })),
        loadIdentityOrNone: vi.fn(() => {
          throw new Error('keystore unavailable');
        }),
      },
    });

    const result = await lifecycle.authenticate();

    expect(result.access_token).toBe('tok-auth');
    expect(client._state).toBe('authenticated');
    expect(client._identity).toMatchObject({
      aid: 'alice.agentid.pub',
      access_token: 'tok-auth',
      refresh_token: 'refresh-auth',
      access_token_expires_at: 12345,
    });
    expect(client._lastError).toBeNull();
    expect(client._lastErrorCode).toBeNull();
  });

  it('authenticate 认证 RPC 失败时回到 standby 并记录错误', async () => {
    const err = new Error('login failed');
    const { lifecycle, client } = createLifecycle({
      _auth: {
        authenticate: vi.fn(async () => {
          throw err;
        }),
        loadIdentityOrNone: vi.fn(),
      },
    });

    await expect(lifecycle.authenticate()).rejects.toThrow('login failed');

    expect(client._state).toBe('standby');
    expect(client._lastError).toBe(err);
    expect(client._lastErrorCode).toBe('AUTHENTICATE_FAILED');
  });

  it('connect 从自动 authenticate 结果复用 token/gateway，并透传短连接选项', async () => {
    const { lifecycle, client } = createLifecycle();

    await lifecycle.connect({
      connection_kind: 'short',
      short_ttl_ms: 15_000,
      call_timeout: 22,
      auto_reconnect: false,
      background_sync: false,
      extra_info: { pid: 42 },
      delivery_mode: { mode: 'queue' },
    });

    expect(client.authenticate).toHaveBeenCalledTimes(1);
    expect(client._sessionParams).toMatchObject({
      gateway: 'ws://returned-gateway/aun',
      access_token: 'tok-auth',
      connection_kind: 'short',
      short_ttl_ms: 15_000,
      auto_reconnect: false,
      background_sync: false,
      extra_info: { pid: 42 },
      delivery_mode: { mode: 'queue' },
    });
    expect(client._transport.setTimeout).toHaveBeenCalledWith(22_000);
    expect(client._connectOnce).toHaveBeenCalledWith(
      expect.objectContaining({ gateway: 'ws://returned-gateway/aun', access_token: 'tok-auth' }),
      true,
    );
    expect(client._state).toBe('ready');
  });

  it('connect 在 authenticated 状态复用已缓存 token，不重新 authenticate', async () => {
    const { lifecycle, client } = createLifecycle({
      _state: 'authenticated',
      _gatewayUrl: 'ws://cached-gateway/aun',
      _identity: { aid: 'alice.agentid.pub', access_token: 'tok-cached' },
    });
    client.authenticate = vi.fn();

    await lifecycle.connect({ auto_reconnect: false });

    expect(client.authenticate).not.toHaveBeenCalled();
    expect(client._sessionParams).toMatchObject({
      gateway: 'ws://cached-gateway/aun',
      access_token: 'tok-cached',
      auto_reconnect: false,
    });
  });

  it('connect 可打断 retry_backoff，普通连接失败回到 standby 并记录错误', async () => {
    const err = new Error('gateway down');
    const { lifecycle, client } = createLifecycle({
      _state: 'retry_backoff',
      _gatewayUrl: 'ws://cached-gateway/aun',
      _identity: { aid: 'alice.agentid.pub', access_token: 'tok-cached' },
      _resolveGateways: vi.fn(() => ['ws://gw-1/aun', 'ws://gw-2/aun']),
      _connectOnce: vi.fn(async () => {
        throw err;
      }),
    });

    await expect(lifecycle.connect()).rejects.toThrow('gateway down');

    expect(client._stopReconnect).toHaveBeenCalledTimes(1);
    expect(client._connectOnce).toHaveBeenCalledTimes(2);
    expect(client._nextRetryAt).toBeNull();
    expect(client._state).toBe('standby');
    expect(client._lastError).toBe(err);
    expect(client._lastErrorCode).toBe('CONNECT_FAILED');
  });

  it('connect 拒绝非 standby/authenticated/retry_backoff/connection_failed 状态', async () => {
    const { lifecycle } = createLifecycle({ _state: 'ready' });

    await expect(lifecycle.connect()).rejects.toThrow(`connect not allowed in state ${ConnectionState.READY}`);
  });
});
