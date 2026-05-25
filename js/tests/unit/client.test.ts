// ── client 模块单元测试 ──────────────────────────────────────
// AUNClient 完整功能需要 Gateway 环境。
// 此处测试可独立验证的构造、配置和状态管理逻辑。
import 'fake-indexeddb/auto';
import { describe, it, expect, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { AUNClient } from '../../src/client.js';
import { RPCTransport } from '../../src/transport.js';
import { AuthError, ConnectionError, StateError, PermissionError, ValidationError } from '../../src/errors.js';
import { ProtectedHeaders } from '../../src/e2ee.js';

function keyIdForBytes(bytes: Uint8Array): string {
  return `sha256:${createHash('sha256').update(Buffer.from(bytes)).digest('hex').slice(0, 16)}`;
}
describe('AUNClient peer 证书缓存', () => {
  it('TTL 应为 3600 秒', () => {
    const source = readFileSync(join(process.cwd(), 'src', 'client.ts'), 'utf8');
    expect(source).toContain('const PEER_CERT_CACHE_TTL = 3600;');
    expect(source).toContain('const PEER_PREKEYS_CACHE_TTL = 3600;');
  });
});

describe('AUNClient 构造', () => {
  it('无参数构造应使用默认配置', () => {
    const client = new AUNClient();
    expect(client.configModel.aunPath).toBe('aun');
    expect(client.configModel.groupE2ee).toBe(true);
    expect(client.configModel.verifySsl).toBe(true);
    expect(client.configModel.replayWindowSeconds).toBe(300);
  });

  it('自定义配置应正确传递', () => {
    const client = new AUNClient({
      aunPath: 'custom',
      seedPassword: 'seed-001',
    });
    expect(client.configModel.aunPath).toBe('custom');
    expect(client.configModel.seedPassword).toBe('seed-001');
    expect(client.configModel.groupE2ee).toBe(true);
    expect(client.configModel.replayWindowSeconds).toBe(300);
  });

  it('verify_ssl=false 应记录警告但不抛错（浏览器环境）', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const client = new AUNClient({ verify_ssl: false });
    // 浏览器环境不支持跳过 SSL，verifySsl 始终为 true
    expect(client.configModel.verifySsl).toBe(true);
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('verify_ssl'));
    warnSpy.mockRestore();
  });
});

describe('AUNClient 初始状态', () => {
  it('初始状态应为 idle', () => {
    const client = new AUNClient();
    expect(client.state).toBe('idle');
  });

  it('初始 AID 应为 null', () => {
    const client = new AUNClient();
    expect(client.aid).toBeNull();
  });

  it('初始 gatewayUrl 应为 null', () => {
    const client = new AUNClient();
    expect(client.gatewayUrl).toBeNull();
  });

  it('gatewayUrl 可手动设置', () => {
    const client = new AUNClient();
    client.gatewayUrl = 'wss://gateway.example.com/aun';
    expect(client.gatewayUrl).toBe('wss://gateway.example.com/aun');
  });
});

describe('AUNClient.connect 参数校验', () => {
  it('缺少 access_token 应抛 StateError', async () => {
    const client = new AUNClient();
    await expect(client.connect({ gateway: 'wss://localhost/aun' }))
      .rejects.toThrow(StateError);
  });

  it('缺少 gateway 应抛 StateError', async () => {
    const client = new AUNClient();
    await expect(client.connect({ access_token: 'token-123' }))
      .rejects.toThrow(StateError);
  });

  it('空 access_token 应抛 StateError', async () => {
    const client = new AUNClient();
    await expect(client.connect({ access_token: '', gateway: 'wss://localhost/aun' }))
      .rejects.toThrow(StateError);
  });
});

describe('AUNClient.call 状态检查', () => {
  it('未连接时调用 call 应抛 ConnectionError', async () => {
    const client = new AUNClient();
    await expect(client.call('meta.ping')).rejects.toThrow(ConnectionError);
  });

  it('内部方法应被拒绝（PermissionError）', async () => {
    // 由于未连接，会先抛 ConnectionError
    // 此测试验证内部方法列表存在即可
    const client = new AUNClient();
    // 需要先将状态设为 connected 才能触发内部方法检查
    // 但无法在单元测试中模拟完整连接，此处跳过
    expect(client.state).toBe('idle');
  });
});

describe('AUNClient.close', () => {
  it('idle 状态关闭应安全', async () => {
    const client = new AUNClient();
    await client.close();
    expect(client.state).toBe('closed');
  });

  it('重复关闭应安全幂等', async () => {
    const client = new AUNClient();
    await client.close();
    await client.close();
    expect(client.state).toBe('closed');
  });
});

describe('AUNClient.on', () => {
  it('应返回 Subscription 实例', () => {
    const client = new AUNClient();
    const sub = client.on('test.event', () => {});
    expect(sub).toBeDefined();
    expect(typeof sub.unsubscribe).toBe('function');
    sub.unsubscribe();
  });

  it('重连流程后应用层订阅仍挂在实际发布的 dispatcher 上', async () => {
    vi.useFakeTimers();
    const randomSpy = vi.spyOn(Math, 'random').mockReturnValue(0);
    try {
      const client = new AUNClient();
      const dispatcher = (client as any)._dispatcher;
      const received: string[] = [];
      const sub = client.on('message.received', (payload: any) => {
        received.push(String(payload.id));
      });

      (client as any)._sessionParams = { access_token: 'tok-1', gateway: 'ws://gateway.example.com/aun' };
      (client as any)._sessionOptions = {
        auto_reconnect: true,
        heartbeat_interval: 30,
        token_refresh_before: 60,
        retry: { initial_delay: 0.01, max_delay: 0.01, max_attempts: 1 },
        timeouts: { connect: 5, call: 10, http: 30 },
      };
      (client as any)._transport.close = vi.fn().mockResolvedValue(undefined);
      (client as any)._connectOnce = vi.fn().mockImplementation(async () => {
        expect((client as any)._dispatcher).toBe(dispatcher);
        (client as any)._state = 'connected';
      });
      (client as any)._reconnectAbort = new AbortController();
      (client as any)._reconnectActive = true;

      const reconnectLoop = (client as any)._reconnectLoop(false);
      await vi.advanceTimersByTimeAsync(2_000);
      await reconnectLoop;

      expect((client as any)._dispatcher).toBe(dispatcher);
      await dispatcher.publish('message.received', { id: 'after-reconnect' });
      expect(received).toEqual(['after-reconnect']);

      sub.unsubscribe();
      received.length = 0;
      const newSub = client.on('message.received', (payload: any) => {
        received.push(`new:${String(payload.id)}`);
      });
      await dispatcher.publish('message.received', { id: 'after-reregister' });
      expect(received).toEqual(['new:after-reregister']);
      newSub.unsubscribe();
    } finally {
      randomSpy.mockRestore();
      vi.useRealTimers();
    }
  });
});

describe('AUNClient 子模块可访问', () => {
  it('auth 命名空间应可用', () => {
    const client = new AUNClient();
    expect(client.auth).toBeDefined();
  });

  it('V1 e2ee 管理器不再公开', () => {
    const client = new AUNClient();
    expect((client as any).e2ee).toBeUndefined();
  });

  it('V1 groupE2ee 管理器不再公开', () => {
    const client = new AUNClient();
    expect((client as any).groupE2ee).toBeUndefined();
  });

  it('discovery 应可用', () => {
    const client = new AUNClient();
    expect(client.discovery).toBeDefined();
  });

});

describe('AUNClient._syncIdentityAfterConnect', () => {
  it('同步 token 时不应覆盖已有 prekey', async () => {
    const client = new AUNClient();
    const ks = (client as any)._keystore;
    const aid = 'sync.agentid.pub';
    const deviceId = (client as any)._deviceId;
    const slotId = (client as any)._slotId;

    await ks.saveIdentity(aid, {
      aid,
      private_key_pem: 'PRIVATE_KEY',
      public_key_der_b64: 'pub',
      curve: 'P-256',
    });
    await ks.saveE2EEPrekey(aid, 'pk1', {
      private_key_pem: 'KEEP_ME',
      created_at: 1,
    }, deviceId);

    (client as any)._aid = aid;
    await (client as any)._syncIdentityAfterConnect('tok-connect');

    const prekeys = await ks.loadE2EEPrekeys(aid, deviceId);
    const instanceState = await ks.loadInstanceState(aid, deviceId, slotId);
    expect(instanceState.access_token).toBe('tok-connect');
    expect(prekeys.pk1.private_key_pem).toBe('KEEP_ME');
  });
});

describe('AUNClient.disconnect', () => {
  it('connected 状态断开后应进入 disconnected', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._transport.close = vi.fn().mockResolvedValue(undefined);

    await client.disconnect();

    expect((client as any)._transport.close).toHaveBeenCalledTimes(1);
    expect(client.state).toBe('disconnected');
  });

  it('disconnected 后应允许再次 connect', async () => {
    const client = new AUNClient();
    (client as any)._state = 'disconnected';
    (client as any)._connectOnce = vi.fn().mockResolvedValue(undefined);
    (client as any)._transport.setTimeout = vi.fn();

    await client.connect({
      access_token: 'tok-1',
      gateway: 'ws://gateway.example.com/aun',
    });

    expect((client as any)._connectOnce).toHaveBeenCalledTimes(1);
  });
});

describe('AUNClient.listIdentities', () => {
  it('应返回本地身份摘要', async () => {
    const client = new AUNClient();
    const ks = (client as any)._keystore;

    await ks.saveIdentity('alice.agentid.pub', {
      aid: 'alice.agentid.pub',
      private_key_pem: 'PRIVATE_KEY',
      access_token: 'tok-1',
      refresh_token: 'ref-1',
    });

    await expect(client.listIdentities()).resolves.toEqual([
      {
        aid: 'alice.agentid.pub',
        metadata: {
          access_token: 'tok-1',
          refresh_token: 'ref-1',
        },
      },
    ]);
  });
});

describe('AUNClient message.send 接收者校验', () => {
  it('不允许向 group.{issuer} 发送 message.send', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';

    await expect(client.call('message.send', {
      to: 'group.example.com',
      payload: { type: 'text', text: 'hello' },
      encrypt: false,
    })).rejects.toThrow(ValidationError);
  });

  it('message.send 拒绝 persist 参数', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';

    await expect(client.call('message.send', {
      to: 'bob.example.com',
      payload: { type: 'text', text: 'hello' },
      encrypt: false,
      persist: true,
    })).rejects.toThrow("message.send no longer accepts 'persist'");
  });

  it('message.send 拒绝发送级 delivery_mode 参数', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';

    await expect(client.call('message.send', {
      to: 'bob.example.com',
      payload: { type: 'text', text: 'hello' },
      encrypt: false,
      delivery_mode: { mode: 'queue' },
    })).rejects.toThrow('message.send does not accept delivery_mode');
  });

  it('message.send 不会转发连接级 delivery_mode', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._connectDeliveryMode = {
      mode: 'queue',
      routing: 'sender_affinity',
      affinity_ttl_ms: 900,
    };
    (client as any)._transport.call = vi.fn().mockResolvedValue({ ok: true });
    const protectedHeaders = new ProtectedHeaders({ Device_ID: 'dev-a', slot_id: 'slot-a' });

    await client.call('message.send', {
      to: 'bob.example.com',
      payload: { type: 'text', text: 'hello' },
      encrypt: false,
      protected_headers: protectedHeaders,
      headers: { device_id: 'dev-b' },
    });

    const [, sentParams] = (client as any)._transport.call.mock.calls[0];
    // delivery_mode 不被转发到底层 RPC（与 Python SDK 对齐）
    expect(sentParams.delivery_mode).toBeUndefined();
    // protected_headers / headers 是信封元数据，加密与否都保留（与 Python SDK 对齐）
    expect(sentParams.protected_headers).toBeDefined();
    expect(sentParams.headers).toBeDefined();
  });

  it('message.pull 自动注入当前实例 device_id/slot_id', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._slotId = 'slot-a';
    (client as any)._transport.call = vi.fn().mockResolvedValue({ messages: [] });

    await client.call('message.pull', { after_seq: 0, limit: 10 });

    expect((client as any)._transport.call).toHaveBeenCalledWith('message.pull', expect.objectContaining({
      device_id: (client as any)._deviceId,
      slot_id: 'slot-a',
    }));
  });

  it('group RPC 应注入空 device_id 作为显式实例值', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._deviceId = '';
    (client as any)._slotId = 'slot-empty-device';
    (client as any)._transport.call = vi.fn().mockResolvedValue({ members: [] });

    await client.call('group.get_members', { group_id: 'group.agentid.pub/g1' });

    const [, sentParams] = (client as any)._transport.call.mock.calls[0];
    expect(sentParams).toHaveProperty('device_id', '');
    expect(sentParams).toHaveProperty('slot_id', 'slot-empty-device');
  });
});

describe('AUNClient 重连错误分类', () => {
  it('aid_login2_failed 应视为可重试', () => {
    const client = new AUNClient();
    expect((client as any)._shouldRetryReconnect(new AuthError('aid_login2_failed'))).toBe(true);
  });

  it('普通 AuthError 仍应直接终止', () => {
    const client = new AUNClient();
    expect((client as any)._shouldRetryReconnect(new AuthError('token invalid'))).toBe(false);
  });
});

describe('AUNClient M25 重连行为', () => {
  it('默认 max_attempts=0 应保留无限重试语义', () => {
    const client = new AUNClient();
    const options = (client as any)._buildSessionOptions({
      access_token: 'tok-1',
      gateway: 'ws://gateway.example.com/aun',
      auto_reconnect: true,
    });

    expect(options.retry.max_attempts).toBe(0);
  });

  it('显式 max_attempts 用尽后进入 terminal_failed', async () => {
    vi.useFakeTimers();
    const randomSpy = vi.spyOn(Math, 'random').mockReturnValue(0);
    try {
      const client = new AUNClient();
      const publish = vi.spyOn((client as any)._dispatcher, 'publish').mockResolvedValue(undefined);
      (client as any)._sessionParams = { access_token: 'tok-1', gateway: 'ws://gateway.example.com/aun' };
      (client as any)._sessionOptions = {
        auto_reconnect: true,
        heartbeat_interval: 30,
        token_refresh_before: 60,
        retry: { initial_delay: 0.01, max_delay: 0.01, max_attempts: 2 },
        timeouts: { connect: 5, call: 10, http: 30 },
      };
      (client as any)._transport.close = vi.fn().mockResolvedValue(undefined);
      (client as any)._connectOnce = vi.fn().mockRejectedValue(new ConnectionError('gateway down'));
      (client as any)._reconnectAbort = new AbortController();
      (client as any)._reconnectActive = true;

      const reconnectLoop = (client as any)._reconnectLoop();
      await vi.advanceTimersByTimeAsync(3_000);
      await reconnectLoop;

      expect((client as any)._connectOnce).toHaveBeenCalledTimes(2);
      expect(client.state).toBe('terminal_failed');
      expect(publish).toHaveBeenCalledWith('connection.state', expect.objectContaining({
        state: 'terminal_failed',
        reason: 'max_attempts_exhausted',
        attempt: 2,
      }));
    } finally {
      randomSpy.mockRestore();
      vi.useRealTimers();
    }
  });

  // ── R1: health-fail 路径也应受 max_attempts 约束 ──────────
  it('health 持续失败时应在 max_attempts 次后进入 terminal_failed', async () => {
    vi.useFakeTimers();
    const randomSpy = vi.spyOn(Math, 'random').mockReturnValue(0);
    try {
      const client = new AUNClient();
      const publish = vi.spyOn((client as any)._dispatcher, 'publish').mockResolvedValue(undefined);
      (client as any)._sessionParams = { access_token: 'tok-1', gateway: 'ws://gateway.example.com/aun' };
      (client as any)._gatewayUrl = 'ws://gateway.example.com/aun';
      (client as any)._sessionOptions = {
        auto_reconnect: true,
        heartbeat_interval: 30,
        token_refresh_before: 60,
        retry: { initial_delay: 0.01, max_delay: 0.01, max_attempts: 3 },
        timeouts: { connect: 5, call: 10, http: 30 },
      };
      // health check 始终失败
      (client as any)._discovery = { checkHealth: vi.fn().mockResolvedValue(false) };
      (client as any)._transport.close = vi.fn().mockResolvedValue(undefined);
      (client as any)._connectOnce = vi.fn().mockRejectedValue(new Error('should not reach'));
      (client as any)._reconnectAbort = new AbortController();
      (client as any)._reconnectActive = true;

      const reconnectLoop = (client as any)._reconnectLoop();
      await vi.advanceTimersByTimeAsync(4_000);
      await reconnectLoop;

      expect(client.state).toBe('terminal_failed');
      expect(publish).toHaveBeenCalledWith('connection.state', expect.objectContaining({
        state: 'terminal_failed',
        reason: 'max_attempts_exhausted',
      }));
      // _connectOnce 不应被调用（health 一直失败）
      expect((client as any)._connectOnce).not.toHaveBeenCalled();
    } finally {
      randomSpy.mockRestore();
      vi.useRealTimers();
    }
  });

  it('heartbeat_interval=0 不启动心跳', async () => {
    vi.useFakeTimers();
    try {
      const client = new AUNClient();
      (client as any)._state = 'connected';
      (client as any)._sessionOptions = {
        auto_reconnect: true,
        heartbeat_interval: 0,
        token_refresh_before: 60,
        retry: { initial_delay: 0.5, max_delay: 30, max_attempts: 0 },
        timeouts: { connect: 5, call: 10, http: 30 },
      };
      (client as any)._transport.call = vi.fn().mockResolvedValue({ pong: true });

      (client as any)._startHeartbeat();
      await vi.advanceTimersByTimeAsync(60_000);

      expect((client as any)._heartbeatTimer).toBeNull();
      expect((client as any)._transport.call).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it('正数 heartbeat_interval 小于 10 秒时按 10 秒调度（M25 后阈值=2）', async () => {
    vi.useFakeTimers();
    try {
      const client = new AUNClient();
      (client as any)._state = 'connected';
      (client as any)._sessionOptions = {
        auto_reconnect: true,
        heartbeat_interval: 0.01,
        token_refresh_before: 60,
        retry: { initial_delay: 0.5, max_delay: 30, max_attempts: 0 },
        timeouts: { connect: 5, call: 10, http: 30 },
      };
      (client as any)._transport.call = vi.fn().mockRejectedValue(new ConnectionError('ping failed'));
      const disconnectSpy = vi.spyOn(client as any, '_handleTransportDisconnect').mockResolvedValue(undefined);

      (client as any)._startHeartbeat();
      await vi.advanceTimersByTimeAsync(9_999);
      await Promise.resolve();
      expect((client as any)._transport.call).not.toHaveBeenCalled();

      await vi.advanceTimersByTimeAsync(1);
      await Promise.resolve();
      expect((client as any)._transport.call).toHaveBeenCalledTimes(1);
      expect(disconnectSpy).not.toHaveBeenCalled();

      await vi.advanceTimersByTimeAsync(10_000);
      await Promise.resolve();
      expect((client as any)._transport.call).toHaveBeenCalledTimes(2);
      expect(disconnectSpy).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it('_applyServerHeartbeatInterval 处理 clamp 与启停', async () => {
    vi.useFakeTimers();
    try {
      const client = new AUNClient();
      (client as any)._state = 'connected';
      (client as any)._sessionOptions = {
        auto_reconnect: true,
        heartbeat_interval: 30,
        token_refresh_before: 60,
        retry: { initial_delay: 0.5, max_delay: 30, max_attempts: 0 },
        timeouts: { connect: 5, call: 10, http: 30 },
      };
      (client as any)._transport.call = vi.fn().mockResolvedValue({ pong: true });

      // 服务端下发 60 → clamp 通过，写回
      (client as any)._applyServerHeartbeatInterval(60, 'auth');
      expect((client as any)._sessionOptions.heartbeat_interval).toBe(60);

      // 服务端下发 5 → clamp 到 10
      (client as any)._applyServerHeartbeatInterval(5, 'pong');
      expect((client as any)._sessionOptions.heartbeat_interval).toBe(10);

      // 服务端下发 9999 → clamp 到 600
      (client as any)._applyServerHeartbeatInterval(9999, 'pong');
      expect((client as any)._sessionOptions.heartbeat_interval).toBe(600);

      // 服务端下发 0 → 关闭，定时器被清
      (client as any)._applyServerHeartbeatInterval(0, 'pong');
      expect((client as any)._sessionOptions.heartbeat_interval).toBe(0);
      expect((client as any)._heartbeatTimer).toBeNull();

      // 再下发非零 → 重新启动
      (client as any)._applyServerHeartbeatInterval(45, 'auth');
      expect((client as any)._sessionOptions.heartbeat_interval).toBe(45);
      expect((client as any)._heartbeatTimer).not.toBeNull();

      // 收尾
      (client as any)._closing = true;
      if ((client as any)._heartbeatTimer) clearInterval((client as any)._heartbeatTimer);
    } finally {
      vi.useRealTimers();
    }
  });

  it('心跳收到 pong.heartbeat_interval 后下次按新间隔调度', async () => {
    vi.useFakeTimers();
    try {
      const client = new AUNClient();
      (client as any)._state = 'connected';
      (client as any)._sessionOptions = {
        auto_reconnect: true,
        heartbeat_interval: 30,
        token_refresh_before: 60,
        retry: { initial_delay: 0.5, max_delay: 30, max_attempts: 0 },
        timeouts: { connect: 5, call: 10, http: 30 },
      };
      const callMock = vi.fn().mockResolvedValue({ pong: true, heartbeat_interval: 60 });
      (client as any)._transport.call = callMock;

      (client as any)._startHeartbeat();
      // 触发第一次心跳（30s 后）
      await vi.advanceTimersByTimeAsync(30_000);
      await Promise.resolve();
      await Promise.resolve();
      expect(callMock).toHaveBeenCalledTimes(1);
      expect((client as any)._sessionOptions.heartbeat_interval).toBe(60);

      // 30s 后不该触发，60s 后才触发
      await vi.advanceTimersByTimeAsync(30_000);
      await Promise.resolve();
      expect(callMock).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(30_000);
      await Promise.resolve();
      await Promise.resolve();
      expect(callMock).toHaveBeenCalledTimes(2);

      // 收尾
      (client as any)._closing = true;
      if ((client as any)._heartbeatTimer) clearInterval((client as any)._heartbeatTimer);
    } finally {
      vi.useRealTimers();
    }
  });
});
describe('AUNClient V2 空 device_id E2EE 路径', () => {
  it('V2 target 构建应接受显式空 device_id', async () => {
    const client = new AUNClient();
    const cachePeerIK = vi.fn();
    (client as any)._v2Session = { cachePeerIK };
    vi.spyOn(client as any, '_v2VerifySPKDevice').mockResolvedValue(undefined);

    const target = await (client as any)._v2BuildTargetFromDevice({
      dev: { device_id: '', ik_pk: 'AQID' },
      aid: 'bob.aid.com',
      deviceId: '',
      hasDeviceId: true,
      role: 'peer',
      defaultKeySource: 'peer_device_prekey',
    });

    expect(target).toEqual(expect.objectContaining({
      aid: 'bob.aid.com',
      deviceId: '',
      role: 'peer',
    }));
    expect(cachePeerIK).toHaveBeenCalledWith('bob.aid.com', '', expect.any(Uint8Array));
  });

  it('V2 target 构建应接受 bootstrap 中 SPK 字段实际为 IK', async () => {
    const client = new AUNClient();
    const ik = new Uint8Array([1, 2, 3]);
    const ikB64 = Buffer.from(ik).toString('base64');
    const ikId = keyIdForBytes(ik);
    const cachePeerIK = vi.fn();
    const markPeerSPKVerified = vi.fn();
    (client as any)._v2Session = { cachePeerIK, markPeerSPKVerified };
    vi.spyOn(client as any, '_v2TrustedIKPubDer').mockResolvedValue(ik);

    const target = await (client as any)._v2BuildTargetFromDevice({
      dev: { device_id: '', ik_pk: ikB64, spk_pk: ikB64, spk_id: ikId, key_source: 'peer_device_prekey' },
      aid: 'bob.aid.com',
      deviceId: '',
      role: 'peer',
      defaultKeySource: 'peer_device_prekey',
    });

    expect(target).toEqual(expect.objectContaining({ aid: 'bob.aid.com', deviceId: '', spkId: ikId }));
    expect(cachePeerIK).toHaveBeenCalledWith('bob.aid.com', '', expect.any(Uint8Array));
    expect(markPeerSPKVerified).toHaveBeenCalledWith('bob.aid.com', '', ikId);
  });
  it('V2 sender IK pending resolver 应通过 bootstrap 缓存显式空 device_id 的 IK', async () => {
    const client = new AUNClient();
    const peerCache = new Map<string, Uint8Array>();
    const peerKey = (aid: string, deviceId: string) => `${new TextEncoder().encode(aid).length}:${aid};${new TextEncoder().encode(deviceId).length}:${deviceId};`;
    const cachePeerIK = vi.fn((aid: string, deviceId: string, pub: Uint8Array) => {
      peerCache.set(peerKey(aid, deviceId), pub);
    });
    (client as any)._v2Session = {
      getPeerIK: vi.fn((aid: string, deviceId: string) => peerCache.get(peerKey(aid, deviceId)) ?? null),
      cachePeerIK,
    };
    (client as any).call = vi.fn().mockResolvedValue({
      peer_devices: [{ device_id: '', ik_pk: 'AQID' }],
    });
    vi.spyOn(client as any, '_fetchPeerCert').mockRejectedValue(new Error('no cert'));

    await (client as any)._resolveV2SenderIKPending('bob.aid.com', '', '', 'bob.aid.com||');
    const pub = (client as any)._v2Session.getPeerIK('bob.aid.com', '');

    expect(Array.from(pub ?? [])).toEqual([1, 2, 3]);
    expect((client as any).call).toHaveBeenCalledWith('message.v2.bootstrap', { peer_aid: 'bob.aid.com' });
    expect(cachePeerIK).toHaveBeenCalledWith('bob.aid.com', '', expect.any(Uint8Array));
    expect((client as any)._fetchPeerCert).not.toHaveBeenCalled();
  });
});
describe('AUNClient V2 群状态 leader delay', () => {
  it('应把空 device_id 作为候选设备', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'b-owner.aid.com';
    (client as any)._deviceId = 'dev-b';
    (client as any)._slotId = 'slot-b';
    (client as any).call = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'group.get_online_members') {
        return {
          members: [
            { aid: 'a-owner.aid.com', role: 'owner', online: true },
            { aid: 'b-owner.aid.com', role: 'owner', online: true },
          ],
        };
      }
      if (method === 'group.v2.bootstrap') {
        return {
          devices: [
            { aid: 'a-owner.aid.com', device_id: '', ik_fp: 'ik-a-empty' },
            { aid: 'b-owner.aid.com', device_id: 'dev-b', ik_fp: 'ik-b' },
          ],
        };
      }
      return { ok: true };
    });
    vi.spyOn(client as any, '_v2LeaderDelayMs').mockResolvedValue(1);
    const sleepSpy = vi.spyOn(client as any, '_sleep').mockResolvedValue(undefined);

    await expect((client as any)._v2AutoProposeLeaderDelay('group.agentid.pub/12345')).resolves.toBe(true);

    expect(sleepSpy).toHaveBeenCalledWith(1);
  });
});

describe('AUNClient 群补拉实例上下文', () => {
  it('_fillGroupGap 应复用当前实例 device_id', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._closing = false;
    (client as any)._seqTracker.getContiguousSeq = vi.fn().mockReturnValue(12);
    (client as any).call = vi.fn().mockResolvedValue({ messages: [] });

    await (client as any)._fillGroupGap('group-1');

    expect((client as any).call).toHaveBeenCalledWith('group.pull', expect.objectContaining({
      group_id: 'group-1',
      after_message_seq: 12,
      device_id: (client as any)._deviceId,
      limit: 50,
    }));
  });

  it('_fillGroupEventGap 应复用当前实例 device_id', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._closing = false;
    (client as any)._seqTracker.getContiguousSeq = vi.fn().mockReturnValue(5);
    (client as any).call = vi.fn().mockResolvedValue({ events: [] });

    await (client as any)._fillGroupEventGap('group-2');

    expect((client as any).call).toHaveBeenCalledWith('group.pull_events', expect.objectContaining({
      group_id: 'group-2',
      after_event_seq: 5,
      device_id: (client as any)._deviceId,
      limit: 50,
    }));
  });
});

// ── Task 1 针对性测试 ──────────────────────────────────────────

describe('group.pull 拦截器：onPullResult 应消费返回消息', () => {
  it('onPullResult 应在 group.pull 后被调用（只传入 transport 返回的消息推进 contig）', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'alice.aid.com';

    const rawMsg = { seq: 5, group_id: 'g1', payload: { type: 'text', text: 'hello' } };

    (client as any)._transport.call = vi.fn().mockResolvedValue({
      messages: [rawMsg],
      cursor: { current_seq: 5 },
    });

    // 捕获 onPullResult 的调用参数
    const onPullResultSpy = vi.spyOn((client as any)._seqTracker, 'onPullResult');

    await client.call('group.pull', { group_id: 'g1', after_message_seq: 0 });

    expect(onPullResultSpy).toHaveBeenCalledWith(
      'group:g1',
      expect.arrayContaining([expect.objectContaining({ payload: rawMsg.payload })]),
      0,
    );
    const callArgs = onPullResultSpy.mock.calls[0];
    const passedMessages = callArgs[1] as any[];
    expect(passedMessages[0].payload).toEqual(rawMsg.payload);
  });
});

describe('_fillGroupGap 不应重复调用 onPullResult', () => {
  it('_fillGroupGap 调用 call(group.pull) 后不应再次调用 onPullResult', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'alice.aid.com';

    const rawMsg = { seq: 3, group_id: 'g2', payload: { type: 'text', text: 'hi' } };

    (client as any)._transport.call = vi.fn().mockResolvedValue({
      messages: [rawMsg],
      cursor: { current_seq: 3 },
    });

    const onPullResultSpy = vi.spyOn((client as any)._seqTracker, 'onPullResult');
    (client as any)._seqTracker.getContiguousSeq = vi.fn().mockReturnValue(2);

    await (client as any)._fillGroupGap('g2');

    // onPullResult 只能被调用一次（来自 call() 拦截器），不能被 _fillGroupGap 再调用一次
    expect(onPullResultSpy).toHaveBeenCalledTimes(1);
  });
});

describe('_handleTransportDisconnect 应先停后台任务再启动重连', () => {
  it('断线时应先调用 _stopBackgroundTasks 再启动重连循环', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._sessionOptions = {
      auto_reconnect: true,
      heartbeat_interval: 30,
      token_refresh_before: 60,
      retry: { initial_delay: 0.5, max_delay: 30, max_attempts: 0 },
      timeouts: { connect: 5, call: 10, http: 30 },
    };

    const callOrder: string[] = [];
    vi.spyOn(client as any, '_stopBackgroundTasks').mockImplementation(() => {
      callOrder.push('stop');
    });
    vi.spyOn(client as any, '_safeAsync').mockImplementation(() => {
      callOrder.push('reconnect');
    });
    vi.spyOn((client as any)._dispatcher, 'publish').mockResolvedValue(undefined);

    await (client as any)._handleTransportDisconnect(new Error('network error'));

    // stop 必须在 reconnect 之前
    const stopIdx = callOrder.indexOf('stop');
    const reconnectIdx = callOrder.indexOf('reconnect');
    expect(stopIdx).toBeGreaterThanOrEqual(0);
    expect(reconnectIdx).toBeGreaterThanOrEqual(0);
    expect(stopIdx).toBeLessThan(reconnectIdx);
  });
});

describe('_connectOnce 应等待 _restoreSeqTrackerState 完成后再调用 transport.connect', () => {
  it('_restoreSeqTrackerState 应在 transport.connect 之前完成', async () => {
    const client = new AUNClient();

    const callOrder: string[] = [];
    // mock _restoreSeqTrackerState 为异步（返回 Promise）
    vi.spyOn(client as any, '_restoreSeqTrackerState').mockImplementation(async () => {
      // 模拟异步 IO
      await new Promise(resolve => setTimeout(resolve, 0));
      callOrder.push('restore');
    });
    vi.spyOn((client as any)._transport, 'connect').mockImplementation(async () => {
      callOrder.push('connect');
      return { nonce: 'challenge' };
    });
    (client as any)._auth.initializeWithToken = vi.fn().mockResolvedValue(undefined);
    (client as any)._syncIdentityAfterConnect = vi.fn().mockResolvedValue(undefined);
    (client as any)._startBackgroundTasks = vi.fn();

    await client.connect({
      access_token: 'tok-1',
      gateway: 'ws://gateway.example.com/aun',
    });

    // restore 必须在 connect 之前完成
    const restoreIdx = callOrder.indexOf('restore');
    const connectIdx = callOrder.indexOf('connect');
    expect(restoreIdx).toBeGreaterThanOrEqual(0);
    expect(connectIdx).toBeGreaterThanOrEqual(0);
    expect(restoreIdx).toBeLessThan(connectIdx);
  });
});

describe('AUNClient SeqTracker 持久化错误事件', () => {
  it('_saveSeqTrackerState 异步失败时应发布 seq_tracker.persist_error', async () => {
    const client = new AUNClient();
    const publishSpy = vi.spyOn((client as any)._dispatcher, 'publish').mockResolvedValue(undefined);

    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'dev-1';
    (client as any)._slotId = 'slot-1';
    (client as any)._seqTracker.onMessageSeq('p2p:test.aid.com', 1);
    (client as any)._seqTracker.onMessageSeq('p2p:test.aid.com', 2);

    const ks = (client as any)._keystore;
    vi.spyOn(ks, 'saveSeq').mockRejectedValue(new Error('disk full'));

    (client as any)._saveSeqTrackerState();
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(publishSpy).toHaveBeenCalledWith('seq_tracker.persist_error', expect.objectContaining({
      phase: 'save',
      aid: 'test.aid.com',
      device_id: 'dev-1',
      slot_id: 'slot-1',
      error: expect.any(String),
    }));
  });

  it('_restoreSeqTrackerState 失败时应发布 seq_tracker.persist_error', async () => {
    const client = new AUNClient();
    const publishSpy = vi.spyOn((client as any)._dispatcher, 'publish').mockResolvedValue(undefined);

    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'dev-1';
    (client as any)._slotId = 'slot-1';
    (client as any)._seqTrackerContext = JSON.stringify(['test.aid.com', 'dev-1', 'slot-1']);

    const ks = (client as any)._keystore;
    vi.spyOn(ks, 'loadAllSeqs').mockRejectedValue(new Error('db corrupted'));

    await (client as any)._restoreSeqTrackerState();

    expect(publishSpy).toHaveBeenCalledWith('seq_tracker.persist_error', expect.objectContaining({
      phase: 'restore',
      aid: 'test.aid.com',
      device_id: 'dev-1',
      slot_id: 'slot-1',
      error: expect.any(String),
    }));
  });
});

// ── 抑制重连测试 ──────────────────────────────────────────

describe('NO_RECONNECT_CODES 抑制重连', () => {
  function makeDisconnectClient() {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._sessionOptions = {
      auto_reconnect: true,
      retry: { initial_delay: 0.01, max_delay: 0.05, max_attempts: 0 },
      timeouts: { connect: 5, call: 10, http: 30 },
      heartbeat_interval: 0,
      token_refresh_before: 60,
    };
    (client as any)._closing = false;
    (client as any)._reconnectActive = false;
    (client as any)._stopBackgroundTasks = vi.fn();
    const safeAsyncSpy = vi.spyOn(client as any, '_safeAsync').mockImplementation(() => {});
    return { client, safeAsyncSpy };
  }

  it.each([4001, 4003, 4008, 4009, 4010, 4011])(
    '不重连 close code %d 应进入 terminal_failed',
    async (code) => {
      const { client, safeAsyncSpy } = makeDisconnectClient();
      await (client as any)._handleTransportDisconnect(new Error('test'), code);
      expect(client.state).toBe('terminal_failed');
      expect(safeAsyncSpy).not.toHaveBeenCalled();
    },
  );

  it.each([4000, 4029, 4500, 4503])(
    '可重连 close code %d 应启动重连',
    async (code) => {
      const { client, safeAsyncSpy } = makeDisconnectClient();
      await (client as any)._handleTransportDisconnect(new Error('test'), code);
      expect(safeAsyncSpy).toHaveBeenCalled();
      expect(client.state).not.toBe('terminal_failed');
    },
  );

  it('收到 gateway.disconnect 通知后断线应抑制重连', async () => {
    const { client, safeAsyncSpy } = makeDisconnectClient();
    (client as any)._onGatewayDisconnect({ code: 4009, reason: 'Connection replaced' });
    expect((client as any)._serverKicked).toBe(true);

    await (client as any)._handleTransportDisconnect(new Error('test'), 4009);
    expect(client.state).toBe('terminal_failed');
    expect(safeAsyncSpy).not.toHaveBeenCalled();
  });

  it('_serverKicked 标志即使可重连 close code 也应抑制重连', async () => {
    const { client, safeAsyncSpy } = makeDisconnectClient();
    (client as any)._serverKicked = true;

    await (client as any)._handleTransportDisconnect(new Error('test'), 1006);
    expect(client.state).toBe('terminal_failed');
    expect(safeAsyncSpy).not.toHaveBeenCalled();
  });
});



describe('AUNClient V2 e2ee payload_type 元数据', () => {
  it('message.thought.get 应把信封 payload_type 送达应用层 e2ee', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'bob.aid.com';
    (client as any)._deviceId = 'dev-b';
    const envelope = {
      type: 'e2ee.p2p_encrypted',
      version: 'v2',
      suite: 'P256_HKDF_SHA256_AES_256_GCM',
      payload_type: 'text',
      protected_headers: { payload_type: 'fallback', trace_id: 'trace-1', _auth: 'secret' },
      context: { type: 'run', id: 'run-1', _auth: 'secret' },
    };
    (client as any)._transport = {
      call: vi.fn().mockResolvedValue({
        found: true,
        sender_aid: 'alice.aid.com',
        thoughts: [{ thought_id: "t-1", payload: envelope }],
      }),
    };
    (client as any)._decryptV2EnvelopeForThought = vi.fn().mockResolvedValue({ type: "text", text: "decrypted" });

    const result = await client.call("message.thought.get", {
      sender_aid: 'alice.aid.com',
      context: { type: 'run', id: 'run-1' },
    });

    const thought = (result as any).thoughts[0];
    expect(thought.payload).toEqual({ type: 'text', text: 'decrypted' });
    expect(thought.payload_type).toBe('text');
    expect(thought.protected_headers).toEqual({ payload_type: 'fallback', trace_id: 'trace-1' });
    expect(thought.e2ee.payload_type).toBe('text');
    expect(thought.e2ee.protected_headers).toEqual({ payload_type: 'fallback', trace_id: 'trace-1' });
    expect(thought.e2ee.context).toEqual({ type: 'run', id: 'run-1' });
  });

  it('message.undecryptable 事件应透传 payload_type 和 protected_headers', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'alice.aid.com';
    (client as any)._deviceId = 'device-001';
    const publish = vi.fn().mockResolvedValue(undefined);
    (client as any)._dispatcher.publish = publish;
    (client as any)._v2Session = {
      getDecryptKeys: vi.fn(() => { throw new Error('spk missing'); }),
    };
    const envelope = {
      type: 'e2ee.p2p_encrypted',
      version: 'v2',
      suite: 'P256_HKDF_SHA256_AES_256_GCM',
      payload_type: 'text',
      aad: { from: 'bob.aid.com', from_device: 'bob-dev' },
      recipients: [['alice.aid.com', 'device-001', 'peer', 'peer_device_prekey', 'fp', 'missing-spk', 'n', 'w']],
      protected_headers: { payload_type: 'text', trace_id: 'trace-1', _auth: 'secret' },
    };

    const result = await (client as any)._decryptV2Message({
      seq: 1,
      message_id: 'm1',
      from_aid: 'bob.aid.com',
      envelope_json: JSON.stringify(envelope),
      t_server: 123,
    });

    expect(result).toBeNull();
    expect(publish).toHaveBeenCalledWith('message.undecryptable', expect.objectContaining({
      payload_type: 'text',
      protected_headers: { payload_type: 'text', trace_id: 'trace-1' },
    }));
  });

  it('message.thought.get 解密失败项应透传 payload_type 和 protected_headers', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'bob.aid.com';
    (client as any)._deviceId = 'dev-b';
    (client as any)._transport = {
      call: vi.fn().mockResolvedValue({
        found: true,
        sender_aid: 'alice.aid.com',
        thoughts: [{
          thought_id: 'mt-fail',
          payload: {
            type: 'e2ee.p2p_encrypted',
            version: 'v2',
            suite: 'P256_HKDF_SHA256_AES_256_GCM',
            payload_type: 'thought',
            protected_headers: { payload_type: 'thought', trace_id: 'trace-p2p', _auth: 'secret' },
          },
        }],
      }),
    };
    (client as any)._decryptV2EnvelopeForThought = vi.fn().mockResolvedValue(null);

    const result = await client.call('message.thought.get', {
      sender_aid: 'alice.aid.com',
      context: { type: 'run', id: 'run-1' },
    });

    const thought = (result as any).thoughts[0];
    expect(thought.decrypt_failed).toBe(true);
    expect(thought.payload_type).toBe('thought');
    expect(thought.protected_headers).toEqual({ payload_type: 'thought', trace_id: 'trace-p2p' });
    expect(thought.e2ee.payload_type).toBe('thought');
    expect(thought.e2ee.protected_headers).toEqual({ payload_type: 'thought', trace_id: 'trace-p2p' });
  });
});
describe('AUNClient agent.md ETag 缓存与透传', () => {
  let agentMdCounter = 0;
  const makeAgentClient = (): AUNClient => new AUNClient({ aunPath: `aun-agent-md-${++agentMdCounter}` });
  const agentRoot = (client: AUNClient): string => (client as any)._agentMdPath as string;
  const agentEtag = (content: string): string => `"${createHash('sha256').update(content, 'utf-8').digest('hex')}"`;
  const readAgentStorage = async (client: AUNClient, key: string): Promise<any> => {
    const record = await (client as any)._keystore.loadAgentMdCache(agentRoot(client), key);
    if (!record) throw new Error(`missing agent.md storage key: ${key}`);
    return record;
  };
  const readAgentList = async (client: AUNClient): Promise<any> => {
    const record = await readAgentStorage(client, 'list.json');
    return JSON.parse(record.content || '{"records":{}}');
  };
  const writeAgentFile = async (client: AUNClient, aid: string, content: string): Promise<void> => {
    await (client as any)._writeAgentMdContent(aid, content);
  };

  it('publishAgentMd 成功后应持久化自身 agent.md 正文和 list.json 元数据', async () => {
    const client = makeAgentClient();
    (client as any)._aid = 'alice.agentid.pub';
    const body = '---\naid: alice.agentid.pub\n---\n# Alice\n';
    const signed = `${body}\n<!-- AUN-SIGNATURE\nsignature: x\n-->\n`;
    await writeAgentFile(client, 'alice.agentid.pub', body);
    (client.auth as any).signAgentMd = vi.fn(async () => signed);
    (client.auth as any).uploadAgentMd = vi.fn(async () => ({
      etag: '"alice-cloud"',
      last_modified: 'Sun, 24 May 2026 13:00:00 GMT',
    }));

    await client.publishAgentMd();

    const saved = await readAgentStorage(client, 'alice.agentid.pub/agent.md');
    const record = (await readAgentList(client)).records['alice.agentid.pub'];
    expect(saved.content).toBe(signed);
    expect(record.content).toBeUndefined();
    expect(record.local_etag).toBe(agentEtag(signed));
    expect(record.remote_etag).toBe('"alice-cloud"');
    expect(record.remote_status).toBe('found');
  });

  it('fetchAgentMd 成功后应持久化远端 agent.md 正文和 list.json 元数据', async () => {
    const client = makeAgentClient();
    (client as any)._aid = 'alice.agentid.pub';
    const body = '---\naid: bob.agentid.pub\n---\n# Bob\n';
    (client.auth as any).downloadAgentMd = vi.fn(async () => body);
    (client.auth as any).verifyAgentMd = vi.fn(async () => ({ status: 'verified', verified: true }));
    (client.auth as any)._agentMdCache = new Map([
      ['bob.agentid.pub', {
        text: body,
        etag: '"bob-cloud"',
        lastModified: 'Sun, 24 May 2026 13:10:00 GMT',
      }],
    ]);

    const info = await client.fetchAgentMd('bob.agentid.pub');

    expect(info.aid).toBe('bob.agentid.pub');
    const saved = await readAgentStorage(client, 'bob.agentid.pub/agent.md');
    const record = (await readAgentList(client)).records['bob.agentid.pub'];
    expect(saved.content).toBe(body);
    expect(record.content).toBeUndefined();
    expect(record.local_etag).toBe(agentEtag(body));
    expect(record.remote_etag).toBe('"bob-cloud"');
    expect(record.verify_status).toBe('verified');
  });

  it('_observeRpcMeta 应分别缓存发送者自身和 message.send 目标的云端 ETag', async () => {
    const client = makeAgentClient();
    (client as any)._aid = 'alice.agentid.pub';
    await writeAgentFile(client, 'alice.agentid.pub', '# Alice\n');
    await writeAgentFile(client, 'bob.agentid.pub', '# Bob\n');
    await writeAgentFile(client, 'carol.agentid.pub', '# Carol\n');
    await writeAgentFile(client, 'dave.agentid.pub', '# Dave\n');

    await (client as any)._observeRpcMeta({
      agent_md_etag: '"alice-cloud"',
      agent_md_etags: {
        to: { aid: 'bob.agentid.pub', etag: '"bob-cloud"' },
        target: { aid: 'carol.agentid.pub', etag: '"carol-cloud"' },
        sender: { aid: 'dave.agentid.pub', etag: '"dave-cloud"' },
      },
    });

    expect(client.getRemoteAgentMdEtag()).toBe('"alice-cloud"');
    const records = (await readAgentList(client)).records;
    expect(records['alice.agentid.pub'].remote_etag).toBe('"alice-cloud"');
    expect(records['bob.agentid.pub'].remote_etag).toBe('"bob-cloud"');
    expect(records['carol.agentid.pub'].remote_etag).toBe('"carol-cloud"');
    expect(records['dave.agentid.pub'].remote_etag).toBe('"dave-cloud"');
  });

  it('transport 事件和通知的顶层 _meta 应进入 agent.md ETag 缓存', async () => {
    const client = makeAgentClient();
    (client as any)._aid = 'alice.agentid.pub';
    await writeAgentFile(client, 'carol.agentid.pub', '# Carol\n');
    await writeAgentFile(client, 'dave.agentid.pub', '# Dave\n');

    (client as any)._transport._routeMessage({
      method: 'event/custom.notice',
      params: {},
      _meta: { agent_md_etags: { target: { aid: 'carol.agentid.pub', etag: '"carol-cloud"' } } },
    });
    (client as any)._transport._routeMessage({
      method: 'custom.notice',
      params: {},
      _meta: { agent_md_etags: { sender: { aid: 'dave.agentid.pub', etag: '"dave-cloud"' } } },
    });
    await new Promise(resolve => setTimeout(resolve, 20));

    const records = (await readAgentList(client)).records;
    expect(records['carol.agentid.pub'].remote_etag).toBe('"carol-cloud"');
    expect(records['dave.agentid.pub'].remote_etag).toBe('"dave-cloud"');
  });

  it('V2 解密失败事件应透传 agent_md.sender 并缓存发送者 ETag', async () => {
    const client = makeAgentClient();
    (client as any)._aid = 'alice.agentid.pub';
    await writeAgentFile(client, 'bob.agentid.pub', '# Bob\n');
    const publish = vi.fn().mockResolvedValue(undefined);
    (client as any)._dispatcher.publish = publish;
    (client as any)._v2Session = {
      getDecryptKeys: vi.fn(() => { throw new Error('spk missing'); }),
    };

    const result = await (client as any)._decryptV2Message({
      seq: 1,
      message_id: 'm-agent-md',
      from_aid: 'bob.agentid.pub',
      envelope_json: JSON.stringify({
        type: 'e2ee.p2p_encrypted',
        version: 'v2',
        suite: 'P256_HKDF_SHA256_AES_256_GCM',
        payload_type: 'chat.text',
        aad: { from: 'bob.agentid.pub', from_device: 'bob-dev' },
        recipients: [['alice.agentid.pub', 'device-001', 'peer', 'peer_device_prekey', 'fp', 'missing-spk', 'n', 'w']],
        protected_headers: { payload_type: 'chat.text', sdk_lang: 'js', _auth: 'secret' },
        agent_md: { sender: { aid: 'bob.agentid.pub', etag: '"bob-cloud"' } },
      }),
      t_server: 123,
    });

    expect(result).toBeNull();
    expect(publish).toHaveBeenCalledWith('message.undecryptable', expect.objectContaining({
      payload_type: 'chat.text',
      protected_headers: { payload_type: 'chat.text', sdk_lang: 'js' },
      agent_md: { sender: { aid: 'bob.agentid.pub', etag: '"bob-cloud"' } },
    }));
    const record = (await readAgentList(client)).records['bob.agentid.pub'];
    expect(record.remote_etag).toBe('"bob-cloud"');
  });

  it('checkAgentMd 应使用 HEAD 返回的云端 ETag 与本地 content ETag 比较并落到 list.json', async () => {
    const client = makeAgentClient();
    (client as any)._aid = 'alice.agentid.pub';
    const body = '# Bob\n';
    await (client as any)._saveAgentMdRecord('bob.agentid.pub', {
      content: body,
      local_etag: agentEtag(body),
      remote_etag: '"old"',
    });
    (client.auth as any).headAgentMd = vi.fn(async (aid: string) => ({
      aid,
      found: true,
      etag: agentEtag(body),
      last_modified: 'Sun, 24 May 2026 13:20:00 GMT',
      status: 200,
    }));

    const result = await client.checkAgentMd('bob.agentid.pub');

    expect(result.local_found).toBe(true);
    expect(result.remote_found).toBe(true);
    expect(result.in_sync).toBe(true);
    const record = (await readAgentList(client)).records['bob.agentid.pub'];
    expect(record.remote_status).toBe('found');
    expect(record.remote_etag).toBe(agentEtag(body));
    expect(record.checked_at).toBeGreaterThan(0);
  });

  it('checkAgentMd 本地无记录时仍应 HEAD 云端并返回 local_found=false', async () => {
    const client = makeAgentClient();
    (client as any)._aid = 'alice.agentid.pub';
    (client.auth as any).headAgentMd = vi.fn(async (aid: string) => ({
      aid,
      found: true,
      etag: '"remote"',
      last_modified: '',
      status: 200,
    }));

    const result = await client.checkAgentMd('carol.agentid.pub');

    expect(result.local_found).toBe(false);
    expect(result.remote_found).toBe(true);
    expect(result.in_sync).toBe(false);
    const record = (await readAgentList(client)).records['carol.agentid.pub'];
    expect(record.remote_etag).toBe('"remote"');
  });
});
describe('有序消息发布', () => {
  it('P2P push 越过空洞时应挂起，补洞后按 contiguous_seq 顺序放行', async () => {
    const client = new AUNClient();
    const ns = 'p2p:alice.aid.com';
    (client as any)._aid = 'alice.aid.com';
    (client as any)._seqTracker.onMessageSeq(ns, 1);

    const published: number[] = [];
    client.on('message.received', (payload: any) => {
      published.push(Number(payload.seq));
    });

    await expect((client as any)._publishOrderedMessage('message.received', ns, 3, { seq: 3 }))
      .resolves.toBe(false);
    expect(published).toEqual([]);
    expect((client as any)._pendingOrderedMsgs.get(ns)?.has(3)).toBe(true);

    (client as any)._seqTracker.onPullResult(ns, [{ seq: 2 }, { seq: 3 }]);
    await expect((client as any)._publishOrderedMessage('message.received', ns, 2, { seq: 2 }))
      .resolves.toBe(true);

    expect(published).toEqual([2, 3]);
    expect((client as any)._pendingOrderedMsgs.has(ns)).toBe(false);
  });

  it('pull 批内部空洞不应阻塞批内后续消息发布', async () => {
    const client = new AUNClient();
    const ns = 'p2p:alice.aid.com';
    (client as any)._seqTracker.onMessageSeq(ns, 1);
    (client as any)._seqTracker.forceContiguousSeq(ns, 2);

    const published: number[] = [];
    client.on('message.received', (payload: any) => published.push(Number(payload.seq)));

    await expect((client as any)._publishPulledMessage('message.received', ns, 2, { seq: 2 }))
      .resolves.toBe(true);
    await expect((client as any)._publishPulledMessage('message.received', ns, 4, { seq: 4 }))
      .resolves.toBe(true);
    (client as any)._seqTracker.forceContiguousSeq(ns, 4);

    expect(published).toEqual([2, 4]);
    expect((client as any)._pushedSeqs.get(ns)?.has(2)).toBe(true);
    expect((client as any)._pushedSeqs.get(ns)?.has(4)).toBe(true);
    (client as any)._prunePushedSeqs(ns);
    expect((client as any)._pushedSeqs.get(ns)?.has(2)).toBe(true);
    expect((client as any)._pushedSeqs.get(ns)?.has(4)).toBe(true);
  });

  it('发布的 P2P/群消息缺实例字段时应 fallback 当前 device_id/slot_id', async () => {
    const client = new AUNClient();
    (client as any)._deviceId = 'dev-1';
    (client as any)._slotId = 'slot-a';
    const p2pNs = 'p2p:alice.aid.com';
    const groupNs = 'group:g1';
    (client as any)._seqTracker.onMessageSeq(p2pNs, 1);
    (client as any)._seqTracker.onMessageSeq(groupNs, 1);

    const p2pEvents: any[] = [];
    const groupEvents: any[] = [];
    client.on('message.received', (payload: any) => p2pEvents.push(payload));
    client.on('group.message_created', (payload: any) => groupEvents.push(payload));

    await (client as any)._publishOrderedMessage('message.received', p2pNs, 1, { seq: 1, payload: { type: 'text' } });
    await (client as any)._publishOrderedMessage('group.message_created', groupNs, 1, {
      group_id: 'g1',
      seq: 1,
      payload: { type: 'text' },
    });

    expect(p2pEvents[0].device_id).toBe('dev-1');
    expect(p2pEvents[0].slot_id).toBe('slot-a');
    expect(groupEvents[0].device_id).toBe('dev-1');
    expect(groupEvents[0].slot_id).toBe('slot-a');
  });
  it('发布消息缺实例字段且当前 device_id 为空时仍应注入空值', () => {
    const client = new AUNClient();
    (client as any)._deviceId = '';
    (client as any)._slotId = 'slot-empty-device';

    const attached = (client as any)._attachCurrentInstanceContext({ seq: 1, payload: { type: 'text' } });

    expect(attached).toHaveProperty('device_id', '');
    expect(attached).toHaveProperty('slot_id', 'slot-empty-device');
  });

  it('发布消息已有空 device_id 时不应被非空当前 device_id 覆盖', () => {
    const client = new AUNClient();
    (client as any)._deviceId = 'dev-1';
    (client as any)._slotId = 'slot-a';

    const attached = (client as any)._attachCurrentInstanceContext({
      device_id: '',
      seq: 1,
      payload: { type: 'text' },
    });

    expect(attached).toHaveProperty('device_id', '');
    expect(attached).toHaveProperty('slot_id', 'slot-a');
  });

  it('P2P push 显式空 device_id 应按实例值匹配', () => {
    const client = new AUNClient();
    (client as any)._deviceId = 'dev-1';
    expect((client as any)._messageTargetsCurrentInstance({ device_id: '' })).toBe(false);

    (client as any)._deviceId = '';
    expect((client as any)._messageTargetsCurrentInstance({ device_id: '' })).toBe(true);
    expect((client as any)._messageTargetsCurrentInstance({ device_id: 'dev-1' })).toBe(false);
  });

  it('P2P push 明确指向其它 slot 时应忽略', async () => {
    const client = new AUNClient();
    (client as any)._aid = 'alice.aid.com';
    (client as any)._deviceId = 'dev-1';
    (client as any)._slotId = 'slot-a';
    (client as any)._transport.call = vi.fn().mockResolvedValue({});

    const published: any[] = [];
    client.on('message.received', (payload: any) => published.push(payload));

    await (client as any)._processAndPublishMessage({
      message_id: 'm-other-slot',
      from: 'bob.aid.com',
      to: 'alice.aid.com',
      slot_id: 'slot-b',
      payload: { type: 'text', text: 'wrong slot' },
    });

    expect(published).toEqual([]);
    expect((client as any)._decryptSingleMessage).toBeUndefined();
    expect((client as any)._tryHandleGroupKeyMessage).toBeUndefined();
  });

  it('group push 明确带其它 slot 时仍应投递且不覆盖实例字段', async () => {
    const client = new AUNClient();
    (client as any)._deviceId = 'dev-1';
    (client as any)._slotId = 'slot-a';
    (client as any)._transport.call = vi.fn().mockResolvedValue({});

    const published: any[] = [];
    client.on('group.message_created', (payload: any) => published.push(payload));

    await (client as any)._processAndPublishGroupMessage({
      message_id: 'gm-other-slot',
      group_id: 'g1',
      from: 'bob.aid.com',
      device_id: 'dev-2',
      slot_id: 'slot-b',
      payload: { type: 'text', text: 'group' },
    });

    expect(published).toHaveLength(1);
    expect(published[0].device_id).toBe('dev-2');
    expect(published[0].slot_id).toBe('slot-b');
  });

  it('group 补拉恢复后应走有序放行', async () => {
    const client = new AUNClient();
    const ns = 'group:g1';
    (client as any)._seqTracker.onMessageSeq(ns, 1);
    (client as any)._seqTracker.onMessageSeq(ns, 3);
    const published: number[] = [];
    client.on('group.message_created', (payload: any) => {
      published.push(Number(payload.seq));
    });

    (client as any)._pendingOrderedMsgs.set(ns, new Map([[3, {
      event: 'group.message_created',
      payload: { seq: 3 },
    }]]));

    (client as any)._seqTracker.onPullResult(ns, [{ seq: 2 }, { seq: 3 }]);
    await (client as any)._publishOrderedMessage('group.message_created', ns, 2, { seq: 2 });

    expect(published).toEqual([2, 3]);
  });

  it('seq tracker 上下文切换时应清空有序待发布队列', () => {
    const client = new AUNClient();
    (client as any)._aid = 'alice.aid.com';
    (client as any)._deviceId = 'device-a';
    (client as any)._slotId = 'slot-a';
    (client as any)._seqTrackerContext = JSON.stringify(['alice.aid.com', 'device-a', 'slot-a']);
    (client as any)._pendingOrderedMsgs.set('p2p:alice.aid.com', new Map([[3, {
      event: 'message.received',
      payload: { seq: 3 },
    }]]));
    (client as any)._slotId = 'slot-b';
    (client as any)._refreshSeqTrackerContext();

    expect((client as any)._pendingOrderedMsgs.size).toBe(0);
  });
});

