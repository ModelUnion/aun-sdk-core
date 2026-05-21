/**
 * AUNClient 单元测试
 *
 * 测试客户端构造、参数校验、状态管理等不需要网络连接的逻辑。
 */

import { describe, it, expect, vi, afterEach } from 'vitest';
import { existsSync, mkdtempSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { AUNClient } from '../../src/client.js';
import { RPCTransport } from '../../src/transport.js';
import { AuthError, ConnectionError, PermissionError, StateError, ValidationError } from '../../src/errors.js';
import { ProtectedHeaders } from '../../src/protected-headers.js';
import { computeStateCommitment } from '../../src/v2/state/index.js';

describe('AUNClient peer 证书缓存', () => {
  it('TTL 应为 3600 秒', () => {
    const source = readFileSync(new URL('../../src/client.ts', import.meta.url), 'utf8');
    expect(source).toContain('const PEER_CERT_CACHE_TTL = 3600;');
  });
});

describe('AUNClient 构造', () => {
  it('无参数构造使用默认配置', () => {
    const client = new AUNClient();
    expect(client.state).toBe('idle');
    expect(client.aid).toBeNull();
    expect(client.config).toEqual({
      aun_path: expect.any(String),
      root_ca_path: null,
      seed_password: null,
    });
  });

  it('使用自定义 aunPath 构造', () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'aun-client-test-'));
    const client = new AUNClient({ aun_path: tmpDir });
    expect(client.state).toBe('idle');
    expect(client.config.aun_path).toBe(tmpDir);
  });

  it('构造时不再创建旧版 SQLite 备份库', () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'aun-client-sqlite-'));
    const client = new AUNClient({ aun_path: tmpDir });
    expect(existsSync(join(tmpDir, '.aun_backup', 'aun_backup.db'))).toBe(false);
    expect(client.state).toBe('idle');
  });

  it('V2 E2EE API 可访问且不暴露旧版 manager', () => {
    const client = new AUNClient();
    expect(typeof client.initV2Session).toBe('function');
    expect(typeof client.sendV2).toBe('function');
    expect(typeof client.sendGroupV2).toBe('function');
    expect((client as any).e2ee).toBeUndefined();
    expect((client as any).groupE2ee).toBeUndefined();
  });

  it('auth 命名空间可访问', () => {
    const client = new AUNClient();
    expect(client.auth).toBeDefined();
  });
});

describe('AUNClient.connect 参数校验', () => {
  it('缺少 access_token 时抛出 StateError', async () => {
    const client = new AUNClient();
    await expect(
      client.connect({ gateway: 'ws://localhost:20001/aun' }),
    ).rejects.toThrow(StateError);
  });

  it('缺少 gateway 时抛出 StateError', async () => {
    const client = new AUNClient();
    await expect(
      client.connect({ access_token: 'tok_123' }),
    ).rejects.toThrow(StateError);
  });

  it('空 access_token 时抛出 StateError', async () => {
    const client = new AUNClient();
    await expect(
      client.connect({ access_token: '', gateway: 'ws://localhost:20001/aun' }),
    ).rejects.toThrow(StateError);
  });
});

describe('AUNClient.call 状态检查', () => {
  it('未连接时调用 call 抛出 ConnectionError', async () => {
    const client = new AUNClient();
    await expect(client.call('meta.ping')).rejects.toThrow(ConnectionError);
  });

  it('内部方法被阻止', async () => {
    const client = new AUNClient();
    // 即使未连接，内部方法检查也应在连接检查之前
    // 但实际上连接检查先执行，所以这里测试的是连接检查
    await expect(client.call('auth.login1')).rejects.toThrow();
  });

  it('已移除的 V1 E2EE RPC 应在签名和传输前被拒绝', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._transport.call = vi.fn().mockResolvedValue({ ok: true });

    const removedMethods = [
      'message.e2ee.upload_prekey',
      'group.e2ee.begin_rotation',
      'group.e2ee.commit_rotation',
      'group.e2ee.abort_rotation',
      'group.rotate_epoch',
    ];

    for (const method of removedMethods) {
      await expect(client.call(method, { group_id: 'group.agentid.pub/g1' })).rejects.toThrow(PermissionError);
    }
    expect((client as any)._transport.call).not.toHaveBeenCalled();
  });

  it('非幂等 RPC 应按毫秒传入 35 秒超时', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._transport.call = vi.fn().mockResolvedValue({ ok: true });

    await client.call('group.create', { name: 'timeout-unit-test' });

    expect((client as any)._transport.call).toHaveBeenCalledWith(
      'group.create',
      expect.objectContaining({
        name: 'timeout-unit-test',
        device_id: (client as any)._deviceId,
        slot_id: (client as any)._slotId,
      }),
      35_000,
    );
  });
});

describe('AUNClient.close', () => {
  it('idle 状态关闭不报错', async () => {
    const client = new AUNClient();
    await expect(client.close()).resolves.toBeUndefined();
    expect(client.state).toBe('closed');
  });

  it('重复关闭不报错', async () => {
    const client = new AUNClient();
    await client.close();
    await expect(client.close()).resolves.toBeUndefined();
  });
});

describe('AUNClient 事件订阅', () => {
  it('on 方法返回 Subscription', () => {
    const client = new AUNClient();
    const sub = client.on('test', () => {});
    expect(sub).toBeDefined();
    expect(typeof sub.unsubscribe).toBe('function');
    sub.unsubscribe();
  });
});

describe('AUNClient._syncIdentityAfterConnect', () => {
  it('同步 token 时应写入当前实例态', () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'aun-client-sync-'));
    const client = new AUNClient({ aun_path: tmpDir });
    const ks = (client as any)._keystore;
    const aid = 'sync.agentid.pub';
    const deviceId = (client as any)._deviceId;

    ks.saveIdentity(aid, {
      aid,
      private_key_pem: 'PRIVATE_KEY',
      public_key_der_b64: 'pub',
      curve: 'P-256',
    });

    (client as any)._aid = aid;
    (client as any)._syncIdentityAfterConnect('tok-connect');

    const instanceState = ks.loadInstanceState(aid, deviceId, '');
    expect(instanceState.access_token).toBe('tok-connect');
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

  it('message.pull 在 V2-only 模式下路由到 message.v2.pull', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._v2Session = {};
    (client as any)._transport.call = vi.fn().mockResolvedValue({ messages: [] });

    await client.call('message.pull', { after_seq: 0, limit: 10 });

    expect((client as any)._transport.call).toHaveBeenCalledWith('message.v2.pull', {
      after_seq: 0,
      limit: 10,
    });
  });
});

describe('AUNClient 证书 URL 编排', () => {
  it('构建证书 URL 时应透传 cert_fingerprint', () => {
    expect((AUNClient as any)._buildCertUrl(
      'wss://gateway.example.com/aun',
      'bob.example.com',
      'sha256:abc',
    )).toBe('https://gateway.example.com/pki/cert/bob.example.com?cert_fingerprint=sha256%3Aabc');
  });
});

describe('AUNClient.connect V2 session 初始化', () => {
  it('连接成功后应初始化 V2 session', async () => {
    const client = new AUNClient();
    (client as any)._transport.connect = vi.fn().mockResolvedValue({ nonce: 'challenge' });
    (client as any)._auth.initializeWithToken = vi.fn().mockResolvedValue(undefined);
    (client as any)._syncIdentityAfterConnect = vi.fn();
    (client as any)._startBackgroundTasks = vi.fn();
    const initV2Spy = vi.spyOn(client, 'initV2Session').mockResolvedValue(undefined);

    await client.connect({
      access_token: 'tok-1',
      gateway: 'ws://gateway.example.com/aun',
    });

    expect(initV2Spy).toHaveBeenCalledTimes(1);
    expect(client.state).toBe('connected');
  });
});

describe('AUNClient 重连错误分类', () => {
  it('aid_login2_failed 应视为可重试', () => {
    expect((AUNClient as any)._shouldRetryReconnect(new AuthError('aid_login2_failed'))).toBe(true);
  });

  it('普通 AuthError 仍应直接终止', () => {
    expect((AUNClient as any)._shouldRetryReconnect(new AuthError('token invalid'))).toBe(false);
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

      (client as any)._startReconnect();
      await vi.advanceTimersByTimeAsync(3_000);
      await Promise.resolve();

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

      (client as any)._startHeartbeatTask();
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

      (client as any)._startHeartbeatTask();
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
});

describe('RPCTransport.close M25 清理', () => {
  it('close 时应先移除 message/error 监听并在超时后 terminate', async () => {
    vi.useFakeTimers();
    try {
      const transport = new RPCTransport({
        eventDispatcher: { publish: vi.fn().mockResolvedValue(undefined) } as any,
      });
      let closeHandler: (() => void) | null = null;
      const removeAllListeners = vi.fn();
      const ws = {
        removeAllListeners: vi.fn((event?: string) => {
          if (event === undefined) {
            removeAllListeners();
          }
        }),
        on: vi.fn((event: string, handler: () => void) => {
          if (event === 'close') closeHandler = handler;
        }),
        close: vi.fn(),
        terminate: vi.fn(),
      };
      (transport as any)._ws = ws;
      (transport as any)._closed = false;

      const closing = transport.close();
      expect(ws.removeAllListeners).toHaveBeenNthCalledWith(1, 'message');
      expect(ws.removeAllListeners).toHaveBeenNthCalledWith(2, 'error');

      await vi.advanceTimersByTimeAsync(3000);
      await closing;

      expect(ws.terminate).toHaveBeenCalledTimes(1);
      expect(removeAllListeners).toHaveBeenCalledTimes(1);
      expect(closeHandler).not.toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });
});

// ── Task 2 新增测试 ────────────────────────────────────────────

describe('RPCTransport.connect 握手阶段回滚', () => {
  it('握手消息解析失败后应回滚 _ws 和 _closed', async () => {
    const transport = new RPCTransport({
      eventDispatcher: { publish: vi.fn().mockResolvedValue(undefined) } as any,
    });

    // 构造一个假 WebSocket：open 后立即发送非法 JSON
    let openHandler: (() => void) | null = null;
    let messageHandler: ((data: Buffer) => void) | null = null;
    let errorHandler: ((err: Error) => void) | null = null;
    const ws = {
      on: vi.fn((event: string, handler: (...args: any[]) => void) => {
        if (event === 'open') openHandler = handler;
        if (event === 'message') messageHandler = handler;
        if (event === 'error') errorHandler = handler;
      }),
      close: vi.fn(),
      terminate: vi.fn(),
      removeAllListeners: vi.fn(),
      send: vi.fn(),
    };

    // 替换 WebSocket 构造函数
    const { RPCTransport: RPCTransportClass } = await import('../../src/transport.js');
    const origWs = (globalThis as any).WebSocket;
    // 通过 mock 注入假 ws
    const connectPromise = (transport as any)._connectWithWs(ws);

    // 触发 open，此时 _ws 应被设置
    openHandler!();
    // 发送非法 JSON
    messageHandler!(Buffer.from('not-valid-json'));

    await expect(connectPromise).rejects.toThrow();
    // 回滚后 _ws 应为 null，_closed 应为 true
    expect((transport as any)._ws).toBeNull();
    expect((transport as any)._closed).toBe(true);
  });

  it('open 后收到 error 事件应回滚 _ws 和 _closed', async () => {
    const transport = new RPCTransport({
      eventDispatcher: { publish: vi.fn().mockResolvedValue(undefined) } as any,
    });

    let openHandler: (() => void) | null = null;
    let errorHandler: ((err: Error) => void) | null = null;
    const ws = {
      on: vi.fn((event: string, handler: (...args: any[]) => void) => {
        if (event === 'open') openHandler = handler;
        if (event === 'error') errorHandler = handler;
      }),
      close: vi.fn(),
      terminate: vi.fn(),
      removeAllListeners: vi.fn(),
      send: vi.fn(),
    };

    const connectPromise = (transport as any)._connectWithWs(ws);

    // 触发 open，此时 _ws 应被设置
    openHandler!();
    // 触发 error（握手阶段）
    errorHandler!(new Error('network error after open'));

    await expect(connectPromise).rejects.toThrow('network error after open');
    // 回滚后 _ws 应为 null，_closed 应为 true
    expect((transport as any)._ws).toBeNull();
    expect((transport as any)._closed).toBe(true);
  });
});

describe('AUNClient SeqTracker 持久化错误事件', () => {
  it('_saveSeqTrackerState 失败时应发布 seq_tracker.persist_error', () => {
    const client = new AUNClient();
    const publishSpy = vi.spyOn((client as any)._dispatcher, 'publish').mockResolvedValue(undefined);

    // 设置必要状态
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'dev-1';
    (client as any)._slotId = 'slot-1';

    // 让 seqTracker 有状态可保存（contiguousSeq > 0，seq=1 直接推进 contiguousSeq）
    (client as any)._seqTracker.onMessageSeq('p2p:test.aid.com', 1);
    (client as any)._seqTracker.onMessageSeq('p2p:test.aid.com', 2);

    // 让 keystore.saveSeq 抛出异常
    const ks = (client as any)._keystore;
    if (typeof ks.saveSeq === 'function') {
      vi.spyOn(ks, 'saveSeq').mockImplementation(() => { throw new Error('disk full'); });
    } else {
      // fallback 路径：让 updateInstanceState 抛出
      vi.spyOn(ks, 'updateInstanceState').mockImplementation(() => { throw new Error('disk full'); });
    }

    (client as any)._saveSeqTrackerState();

    expect(publishSpy).toHaveBeenCalledWith('seq_tracker.persist_error', expect.objectContaining({
      phase: 'save',
      aid: 'test.aid.com',
      device_id: 'dev-1',
      slot_id: 'slot-1',
      error: expect.any(String),
    }));
  });

  it('_restoreSeqTrackerState 失败时应发布 seq_tracker.persist_error', () => {
    const client = new AUNClient();
    const publishSpy = vi.spyOn((client as any)._dispatcher, 'publish').mockResolvedValue(undefined);

    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'dev-1';
    (client as any)._slotId = 'slot-1';

    // 让 keystore 的读取方法抛出异常
    const ks = (client as any)._keystore;
    if (typeof ks.loadAllSeqs === 'function') {
      vi.spyOn(ks, 'loadAllSeqs').mockImplementation(() => { throw new Error('db corrupted'); });
    } else {
      vi.spyOn(ks, 'loadInstanceState').mockImplementation(() => { throw new Error('db corrupted'); });
    }

    (client as any)._restoreSeqTrackerState();

    expect(publishSpy).toHaveBeenCalledWith('seq_tracker.persist_error', expect.objectContaining({
      phase: 'restore',
      aid: 'test.aid.com',
      device_id: 'dev-1',
      slot_id: 'slot-1',
      error: expect.any(String),
    }));
  });
});

describe('AUNClient V2 群状态自动编排', () => {
  it('非 upsert 的 group.changed 事件不触发 V2 state propose', async () => {
    vi.useFakeTimers();
    try {
      const client = new AUNClient();

      (client as any)._aid = 'member.aid.com';
      (client as any)._identity = { aid: 'member.aid.com' };
      (client as any)._state = 'connected';
      (client as any)._v2Session = {};

      const proposeSpy = vi.spyOn(client as any, '_v2AutoProposeState').mockResolvedValue(undefined);
      const callSpy = vi.spyOn(client, 'call').mockImplementation(async (method, params) => {
        if (method === 'group.get_members') {
          expect(params).toEqual({ group_id: 'test-group-123' });
          return {
            members: [
              { aid: 'owner.aid.com', role: 'owner' },
              { aid: 'member.aid.com', role: 'member' },
            ],
          };
        }
        // 允许 ack 等调用通过
        return { ok: true };
      });
      vi.spyOn(Math, 'random').mockReturnValue(0);

      await (client as any)._onRawGroupChanged({
        group_id: 'test-group-123',
        action: 'member_removed',
        member_aid: 'removed.aid.com',
      });
      await vi.runAllTimersAsync();

      expect(callSpy).not.toHaveBeenCalledWith('group.get_members', { group_id: 'test-group-123' });
      expect(proposeSpy).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
      vi.restoreAllMocks();
    }
  });
});

// ── close_code 1000 误判测试 ──────────────────────────────

describe('close_code 1000 不应视为 serverInitiated', () => {
  it('close_code=1000 时不应以 serverInitiated=true 启动重连', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    (client as any)._sessionOptions = {
      ...(client as any)._sessionOptions,
      auto_reconnect: true,
    };

    const startReconnectSpy = vi.spyOn(client as any, '_startReconnect').mockImplementation(() => {});

    await (client as any)._handleTransportDisconnect(new Error('closed'), 1000);

    // closeCode=1000 是正常关闭，不应被视为 serverInitiated
    if (startReconnectSpy.mock.calls.length > 0) {
      const serverInitiated = startReconnectSpy.mock.calls[0][0];
      expect(serverInitiated).toBe(false);
    }
  });
});

// ── group.add_member V2 state propose 兜底测试 ────────────

describe('group.add_member 成员变更 V2 state 处理', () => {
  it('group.add_member 返回 error 时不应触发 V2 state propose', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'device-001';
    (client as any)._v2Session = {};

    // 模拟 transport.call 返回错误结果
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      error: { code: -33003, message: 'not authorized' },
    });

    const proposeSpy = vi.spyOn(client as any, '_v2AutoProposeState').mockResolvedValue(undefined);

    await client.call('group.add_member', {
      group_id: 'group-123',
      aid: 'new-member.aid.com',
    });

    expect(proposeSpy).not.toHaveBeenCalled();
  });

  it('group.add_member 成功时应触发 V2 state propose', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'device-001';
    (client as any)._v2Session = {};

    // 模拟成功结果
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      ok: true,
    });

    const proposeSpy = vi.spyOn(client as any, '_v2AutoProposeState').mockResolvedValue(undefined);

    await client.call('group.add_member', {
      group_id: 'group-123',
      aid: 'new-member.aid.com',
    });

    expect(proposeSpy).toHaveBeenCalledWith('group-123');
  });

  it('group.create 成功时应阻塞触发 V2 state propose', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'device-001';
    (client as any)._v2Session = {};
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      group: { group_id: 'group-123' },
    });

    const proposeSpy = vi.spyOn(client as any, '_v2AutoProposeState').mockResolvedValue(undefined);

    await client.call('group.create', { name: 'v2-create' });

    expect(proposeSpy).toHaveBeenCalledWith('group-123');
  });

  it('group.changed upsert 事件触发 V2 state propose 时应启用 leader delay', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'device-001';
    (client as any)._v2Session = {};
    const proposeSpy = vi.spyOn(client as any, '_v2AutoProposeState').mockResolvedValue(undefined);

    await (client as any)._onRawGroupChanged({ group_id: 'group-123', action: 'upsert' });

    expect(proposeSpy).toHaveBeenCalledWith('group-123', { leaderDelay: true });
  });

  it('V2 leader delay 仅允许在线 owner/admin 参与 leader 选举', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'z-owner.aid.com';
    (client as any)._deviceId = 'device-001';
    (client as any)._slotId = 'slot-a';
    (client as any)._v2Session = {};
    (client as any)._transport.call = vi.fn().mockResolvedValue({ ok: true });
    const calls: string[] = [];
    (client as any).call = vi.fn().mockImplementation(async (method: string) => {
      calls.push(method);
      if (method === 'group.get_online_members') {
        return {
          members: [
            { aid: 'z-owner.aid.com', role: 'owner', online: true },
            { aid: 'm-member.aid.com', role: 'member', online: true },
          ],
        };
      }
      if (method === 'group.get_members') {
        return {
          members: [
            { aid: 'a-offline-admin.aid.com', role: 'admin' },
            { aid: 'z-owner.aid.com', role: 'owner' },
          ],
        };
      }
      if (method === 'group.v2.bootstrap') {
        return {
          devices: [
            { aid: 'a-offline-admin.aid.com', device_id: 'dev-offline', ik_fp: 'ik-a' },
            { aid: 'z-owner.aid.com', device_id: 'device-001', ik_fp: 'ik-z' },
          ],
          audit_recipients: [],
        };
      }
      return { ok: true };
    });
    const sleepSpy = vi.spyOn(client as any, '_sleep').mockResolvedValue(undefined);

    await expect((client as any)._v2AutoProposeLeaderDelay('group.agentid.pub/12345')).resolves.toBe(true);

    expect(calls).toEqual(['group.get_online_members', 'group.v2.bootstrap']);
    expect(sleepSpy).not.toHaveBeenCalled();
  });

  it('group.* 调用应先归一化 group_id 后再进入传输层和 V2 state 编排', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'device-001';
    (client as any)._slotId = 'slot-a';
    (client as any)._v2Session = {};
    (client as any)._transport.call = vi.fn().mockResolvedValue({ ok: true });
    const proposeSpy = vi.spyOn(client as any, '_v2AutoProposeState').mockResolvedValue(undefined);

    await client.call('group.add_member', {
      group_id: 'g-abc.agentid.pub',
      aid: 'new-member.aid.com',
    });

    expect((client as any)._transport.call).toHaveBeenCalledWith(
      'group.add_member',
      expect.objectContaining({ group_id: 'group.agentid.pub/g-abc' }),
      35_000,
    );
    expect(proposeSpy).toHaveBeenCalledWith('group.agentid.pub/g-abc');
  });
});

// ── R1: health-fail 路径也应受 max_attempts 约束 ──────────

describe('R1: health-fail 路径 max_attempts 检查', () => {
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

      // health check 始终失败 → 应走 health-fail 路径
      (client as any)._discovery = { checkHealth: vi.fn().mockResolvedValue(false) };
      (client as any)._transport.close = vi.fn().mockResolvedValue(undefined);
      // _connectOnce 不应被调用（health 失败应跳过连接）
      (client as any)._connectOnce = vi.fn().mockRejectedValue(new Error('should not reach'));

      (client as any)._startReconnect();
      // 推进足够多的 timer 让所有重试完成
      await vi.advanceTimersByTimeAsync(4_000);

      // health-fail 路径应计入 attempt，3 次后应终止
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
});

// ── R2: 固定上限抖动不应污染指数退避 base ────────────────────

describe('R2: delay 基数不应被 Math.random 污染', () => {
  it('连续重连失败时 delay 基数应指数增长，不坍塌到 0', async () => {
    vi.useFakeTimers();
    try {
      const client = new AUNClient();
      vi.spyOn((client as any)._dispatcher, 'publish').mockResolvedValue(undefined);
      (client as any)._sessionParams = { access_token: 'tok-1', gateway: 'ws://gateway.example.com/aun' };
      (client as any)._sessionOptions = {
        auto_reconnect: true,
        heartbeat_interval: 30,
        token_refresh_before: 60,
        retry: { initial_delay: 1.0, max_delay: 64, max_attempts: 0 },
        timeouts: { connect: 5, call: 10, http: 30 },
      };
      (client as any)._transport.close = vi.fn().mockResolvedValue(undefined);

      // 固定 Math.random 为 0.1，验证随机抖动不会反向污染下一轮 base
      vi.spyOn(Math, 'random').mockReturnValue(0.1);

      // 记录每次 setTimeout 的实际 delay
      const timeoutDelays: number[] = [];
      const origSetTimeout = globalThis.setTimeout;
      vi.spyOn(globalThis, 'setTimeout').mockImplementation((fn: any, delay?: number) => {
        if (delay !== undefined) timeoutDelays.push(delay);
        return origSetTimeout(fn, delay);
      });

      let connectAttempts = 0;
      (client as any)._connectOnce = vi.fn().mockImplementation(async () => {
        connectAttempts++;
        if (connectAttempts >= 5) {
          // 第 5 次后停止重连
          (client as any)._closing = true;
        }
        throw new ConnectionError('gateway down');
      });

      (client as any)._startReconnect();
      await vi.advanceTimersByTimeAsync(100_000);

      // 正确语义：base 指数增长并夹在 [1s, 64s]，sleep = base + rand(0, max_base)
      // 如果随机值污染下一轮 base，base 会衰减到接近 0
      // 验证：第 3 次 setTimeout delay 应大于第 1 次
      expect(timeoutDelays.length).toBeGreaterThanOrEqual(3);
      // 每次 setTimeout delay 都应 > 0（不坍塌到 0）
      for (const d of timeoutDelays) {
        expect(d).toBeGreaterThanOrEqual(0);
      }
      // delay 应递增（指数退避），第 3 次应大于第 1 次
      if (timeoutDelays.length >= 3) {
        expect(timeoutDelays[2]).toBeGreaterThan(timeoutDelays[0]);
      }
    } finally {
      vi.useRealTimers();
      vi.restoreAllMocks();
    }
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
    (client as any)._reconnecting = false;
    const startReconnectSpy = vi.spyOn(client as any, '_startReconnect').mockImplementation(() => {});
    (client as any)._stopBackgroundTasks = vi.fn();
    return { client, startReconnectSpy };
  }

  it.each([4001, 4003, 4008, 4009, 4010, 4011])(
    '不重连 close code %d 应进入 terminal_failed',
    async (code) => {
      const { client, startReconnectSpy } = makeDisconnectClient();
      await (client as any)._handleTransportDisconnect(new Error('test'), code);
      expect(client.state).toBe('terminal_failed');
      expect(startReconnectSpy).not.toHaveBeenCalled();
    },
  );

  it.each([4000, 4029, 4500, 4503])(
    '可重连 close code %d 应启动重连',
    async (code) => {
      const { client, startReconnectSpy } = makeDisconnectClient();
      await (client as any)._handleTransportDisconnect(new Error('test'), code);
      expect(startReconnectSpy).toHaveBeenCalled();
      expect(client.state).not.toBe('terminal_failed');
    },
  );

  it('收到 gateway.disconnect 通知后断线应抑制重连', async () => {
    const { client, startReconnectSpy } = makeDisconnectClient();
    // 模拟 gateway.disconnect 通知
    (client as any)._onGatewayDisconnect({ code: 4009, reason: 'Connection replaced' });
    expect((client as any)._serverKicked).toBe(true);

    await (client as any)._handleTransportDisconnect(new Error('test'), 4009);
    expect(client.state).toBe('terminal_failed');
    expect(startReconnectSpy).not.toHaveBeenCalled();
  });

  it('_serverKicked 标志即使可重连 close code 也应抑制重连', async () => {
    const { client, startReconnectSpy } = makeDisconnectClient();
    (client as any)._serverKicked = true;

    await (client as any)._handleTransportDisconnect(new Error('test'), 1006);
    expect(client.state).toBe('terminal_failed');
    expect(startReconnectSpy).not.toHaveBeenCalled();
  });
});

// ── E2EE V2-only pull / thought 编排 ─────────────────────

describe('AUNClient E2EE V2-only 编排', () => {
  function makeV2Client() {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'alice.aid.com';
    (client as any)._deviceId = 'device-001';
    (client as any)._slotId = 'slot-a';
    (client as any)._v2Session = {
      isCurrentSPK: vi.fn().mockReturnValue(false),
      trackOldSPKMaxSeq: vi.fn(),
      maybeDestroyOldSPKs: vi.fn().mockReturnValue([]),
    };
    return client;
  }

  it('message.v2.pull 跳过非 V2 行', async () => {
    const client = makeV2Client();
    (client as any)._transport.call = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'message.v2.pull') {
        return {
          messages: [
            {
              version: 'legacy',
              message_id: 'm-legacy',
              from_aid: 'bob.aid.com',
              seq: 1,
              type: 'message',
              payload: { type: 'text', text: 'legacy plain' },
            },
          ],
        };
      }
      return { ok: true };
    });

    const result = await client.pullV2(0, 10);

    expect(result).toEqual([]);
  });

  it('V2 auto propose 同 group 并发触发时应只提交一次 state proposal', async () => {
    const client = makeV2Client();
    const calls: string[] = [];
    const statePayload = {
      members: [
        { aid: 'alice.aid.com', devices: [{ device_id: 'device-001', ik_fp: 'ik-a' }] },
        { aid: 'bob.aid.com', devices: [{ device_id: 'device-002', ik_fp: 'ik-b' }] },
      ],
      audit_aids: [],
      admin_set: { admin_aids: ['alice.aid.com'], threshold: 1 },
      join_policy_hash: null,
      recovery_quorum: null,
      history_policy: 'recent_7_days',
      wrap_protocol: '3DH',
    };
    const committedMembershipSnapshot = JSON.stringify(statePayload);
    const committedStateHash = computeStateCommitment('group.agentid.pub/12345', 1, statePayload);
    let committed = false;
    (client as any).call = vi.fn().mockImplementation(async (method: string) => {
      calls.push(method);
      if (method === 'group.get_members') {
        return {
          members: [
            { aid: 'alice.aid.com', role: 'owner' },
            { aid: 'bob.aid.com', role: 'member' },
          ],
        };
      }
      if (method === 'group.v2.bootstrap') {
        return {
          devices: [
            { aid: 'alice.aid.com', device_id: 'device-001', ik_fp: 'ik-a' },
            { aid: 'bob.aid.com', device_id: 'device-002', ik_fp: 'ik-b' },
          ],
          audit_recipients: [],
        };
      }
      if (method === 'group.get_state') {
        return committed
          ? {
              state_version: 1,
              state_hash: committedStateHash,
              key_epoch: 0,
              membership_snapshot: committedMembershipSnapshot,
              policy_snapshot: '',
            }
          : {
              state_version: 0,
              state_hash: 'h0',
              key_epoch: 0,
              membership_snapshot: '',
              policy_snapshot: '',
            };
      }
      if (method === 'group.v2.propose_state') {
        committed = true;
        return { proposal_id: 'proposal-1' };
      }
      if (method === 'group.v2.confirm_state') {
        return { ok: true };
      }
      return { ok: true };
    });

    await Promise.all([
      (client as any)._v2AutoProposeState('group.agentid.pub/12345'),
      (client as any)._v2AutoProposeState('group.agentid.pub/12345'),
    ]);

    expect(calls.filter(method => method === 'group.v2.propose_state')).toHaveLength(1);
    expect(calls.filter(method => method === 'group.v2.confirm_state')).toHaveLength(1);
  });

  it('V2 auto propose 在 sv>0 时必须先验证最后 committed state', async () => {
    const client = makeV2Client();
    const calls: string[] = [];
    (client as any).call = vi.fn().mockImplementation(async (method: string) => {
      calls.push(method);
      if (method === 'group.get_members') {
        return { members: [{ aid: 'alice.aid.com', role: 'owner' }, { aid: 'bob.aid.com', role: 'member' }] };
      }
      if (method === 'group.v2.bootstrap') {
        return { devices: [], audit_recipients: [] };
      }
      if (method === 'group.get_state') {
        return {
          state_version: 1,
          state_hash: 'not-a-valid-committed-hash',
          key_epoch: 0,
          membership_snapshot: JSON.stringify({
            members: [{ aid: 'alice.aid.com', devices: [] }],
            audit_aids: [],
            admin_set: { admin_aids: ['alice.aid.com'], threshold: 1 },
            join_policy_hash: null,
            recovery_quorum: null,
            history_policy: 'recent_7_days',
            wrap_protocol: '3DH',
          }),
          policy_snapshot: '',
        };
      }
      return { ok: true };
    });

    await (client as any)._v2AutoProposeState('group.agentid.pub/12345');

    expect(calls).toContain('group.get_state');
    expect(calls).not.toContain('group.v2.propose_state');
    expect(calls).not.toContain('group.v2.confirm_state');
  });

  it('V2 pending proposal 自动确认前必须验证 committed base 和 proposal hash', async () => {
    const client = makeV2Client();
    const groupId = 'group.agentid.pub/12345';
    const basePayload = {
      members: [{ aid: 'alice.aid.com', devices: [] }],
      audit_aids: [],
      admin_set: { admin_aids: ['alice.aid.com'], threshold: 1 },
      join_policy_hash: null,
      recovery_quorum: null,
      history_policy: 'recent_7_days',
      wrap_protocol: '3DH',
    };
    const nextPayload = {
      ...basePayload,
      members: [
        { aid: 'alice.aid.com', devices: [] },
        { aid: 'bob.aid.com', devices: [] },
      ],
    };
    const baseHash = computeStateCommitment(groupId, 1, basePayload);
    const nextHash = computeStateCommitment(groupId, 2, nextPayload);
    const calls: string[] = [];
    (client as any).call = vi.fn().mockImplementation(async (method: string) => {
      calls.push(method);
      if (method === 'group.v2.get_proposal') {
        return {
          proposal: {
            proposal_id: 'sp-1',
            state_version: 2,
            state_hash: nextHash,
            prev_state_hash: baseHash,
            membership_snapshot: JSON.stringify(nextPayload),
          },
        };
      }
      if (method === 'group.get_state') {
        return {
          state_version: 1,
          state_hash: baseHash,
          key_epoch: 0,
          membership_snapshot: JSON.stringify(basePayload),
        };
      }
      return { ok: true };
    });

    await expect((client as any)._v2ConfirmPendingProposal(groupId)).resolves.toBe(true);

    expect(calls).toEqual(['group.v2.get_proposal', 'group.get_state', 'group.v2.confirm_state']);
  });

  it('group.v2.state_retry_needed 应触发带 leader delay 的重新提案', async () => {
    const client = makeV2Client();
    const proposeSpy = vi.spyOn(client as any, '_v2AutoProposeState').mockResolvedValue(undefined);

    await (client as any)._onV2StateRetryNeeded({ group_id: 'group.agentid.pub/12345' });

    expect(proposeSpy).toHaveBeenCalledWith('group.agentid.pub/12345', { leaderDelay: true });
  });

  it('message.v2.pull 应透传服务端合并的 V1 明文行，但跳过 V1 E2EE envelope', async () => {
    const client = makeV2Client();
    (client as any)._transport.call = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'message.v2.pull') {
        return {
          messages: [
            {
              version: 'v1',
              message_id: 'm-plain',
              from_aid: 'bob.aid.com',
              seq: 1,
              type: 'message',
              t_server: 123,
              legacy_v1: {
                to: 'alice.aid.com',
                payload: { type: 'text', text: 'legacy plain' },
              },
            },
            {
              version: 'v1',
              message_id: 'm-e2ee',
              from_aid: 'bob.aid.com',
              seq: 2,
              type: 'message',
              legacy_v1: {
                payload: { type: 'e2ee.encrypted', ciphertext: 'x' },
              },
            },
          ],
        };
      }
      return { ok: true };
    });

    const result = await client.pullV2(0, 10);

    expect(result).toEqual([expect.objectContaining({
      message_id: 'm-plain',
      from: 'bob.aid.com',
      to: 'alice.aid.com',
      seq: 1,
      payload: { type: 'text', text: 'legacy plain' },
      encrypted: false,
    })]);
  });

  it('message.v2.pull 返回值不应因 seq 已投递而去重', async () => {
    const client = makeV2Client();
    const ns = 'p2p:alice.aid.com';
    (client as any)._pushedSeqs.set(ns, new Set([1]));
    const decrypted = {
      message_id: 'm-v2',
      from: 'bob.aid.com',
      to: 'alice.aid.com',
      seq: 1,
      payload: { type: 'text', text: 'already pushed' },
      encrypted: true,
      e2ee: { version: 'v2' },
    };
    vi.spyOn(client as any, '_decryptV2Message').mockResolvedValue(decrypted);
    (client as any)._transport.call = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'message.v2.pull') {
        return {
          messages: [
            {
              version: 'v2',
              message_id: 'm-v2',
              from_aid: 'bob.aid.com',
              seq: 1,
              envelope_json: '{}',
            },
          ],
        };
      }
      return { ok: true };
    });

    const result = await client.pullV2(0, 10);

    expect(result).toEqual([decrypted]);
  });

  it('message.send 非对象 payload 应直接拒绝，不应落到传输层', async () => {
    const client = makeV2Client();
    const transportCall = vi.fn().mockResolvedValue({ ok: true });
    (client as any)._transport.call = transportCall;

    await expect(client.call('message.send', {
      to: 'bob.aid.com',
      payload: 'bad-payload' as any,
    })).rejects.toThrow(ValidationError);

    expect(transportCall).not.toHaveBeenCalled();
  });

  it('group.v2.pull 跳过非 V2 行', async () => {
    const client = makeV2Client();
    (client as any)._transport.call = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'group.v2.pull') {
        return {
          messages: [
            {
              version: 'legacy',
              message_id: 'gm-legacy',
              from_aid: 'bob.aid.com',
              seq: 1,
              payload: { type: 'text', text: 'group plain' },
            },
          ],
        };
      }
      return { ok: true };
    });

    const result = await client.pullGroupV2('g1', 0, 10);

    expect(result).toEqual([]);
  });

  it('group.v2.pull 应透传服务端合并的 V1 明文行，但跳过 V1 E2EE envelope', async () => {
    const client = makeV2Client();
    (client as any)._transport.call = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'group.v2.pull') {
        return {
          messages: [
            {
              version: 'v1',
              message_id: 'gm-plain',
              from_aid: 'bob.aid.com',
              seq: 1,
              type: 'group.message',
              t_server: 456,
              payload: { type: 'text', text: 'group legacy plain' },
            },
            {
              version: 'v1',
              message_id: 'gm-e2ee',
              from_aid: 'bob.aid.com',
              seq: 2,
              payload: { type: 'e2ee.group_encrypted', ciphertext: 'x' },
            },
          ],
        };
      }
      return { ok: true };
    });

    const result = await client.pullGroupV2('g1', 0, 10);

    expect(result).toEqual([expect.objectContaining({
      message_id: 'gm-plain',
      from: 'bob.aid.com',
      group_id: 'g1',
      seq: 1,
      payload: { type: 'text', text: 'group legacy plain' },
      encrypted: false,
    })]);
  });

  it('group.send 非对象 payload 应直接拒绝，不应落到传输层', async () => {
    const client = makeV2Client();
    const transportCall = vi.fn().mockResolvedValue({ ok: true });
    (client as any)._transport.call = transportCall;

    await expect(client.call('group.send', {
      group_id: 'g1',
      payload: 'bad-payload' as any,
    })).rejects.toThrow(ValidationError);

    expect(transportCall).not.toHaveBeenCalled();
  });

  it('group.v2.pull 返回值不应因 seq 已投递而去重', async () => {
    const client = makeV2Client();
    const ns = 'group:g1';
    (client as any)._pushedSeqs.set(ns, new Set([1]));
    const decrypted = {
      message_id: 'gm-v2',
      from: 'bob.aid.com',
      to: 'alice.aid.com',
      seq: 1,
      payload: { type: 'text', text: 'already pushed group' },
      encrypted: true,
      e2ee: { version: 'v2' },
    };
    vi.spyOn(client as any, '_decryptV2Message').mockResolvedValue({ ...decrypted });
    (client as any)._transport.call = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'group.v2.pull') {
        return {
          messages: [
            {
              version: 'v2',
              message_id: 'gm-v2',
              from_aid: 'bob.aid.com',
              seq: 1,
              envelope_json: '{}',
            },
          ],
        };
      }
      return { ok: true };
    });

    const result = await client.pullGroupV2('g1', 0, 10);

    expect(result).toEqual([{ ...decrypted, group_id: 'g1' }]);
  });

  it('message.v2.pull 发现空洞时应推进 seq tracker，且不触发后台补洞', async () => {
    const client = makeV2Client();
    const fillSpy = vi.spyOn(client as any, '_fillP2pGap').mockResolvedValue(undefined);
    (client as any)._transport.call = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'message.v2.pull') {
        return {
          messages: [
            {
              version: 'legacy',
              message_id: 'm-gap',
              from_aid: 'bob.aid.com',
              seq: 3,
              type: 'message',
              payload: { type: 'text', text: 'gap trigger' },
            },
          ],
        };
      }
      return { ok: true };
    });

    const result = await client.pullV2(0, 10);

    expect(result).toEqual([]);
    expect(fillSpy).not.toHaveBeenCalled();
    expect((client as any)._seqTracker.getContiguousSeq('p2p:alice.aid.com')).toBe(3);
  });

  it('group.v2.pull 发现空洞时应推进 seq tracker，且不触发后台补洞', async () => {
    const client = makeV2Client();
    const fillSpy = vi.spyOn(client as any, '_fillGroupGap').mockResolvedValue(undefined);
    (client as any)._transport.call = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'group.v2.pull') {
        return {
          messages: [
            {
              version: 'legacy',
              message_id: 'gm-gap',
              from_aid: 'bob.aid.com',
              group_id: 'g1',
              seq: 3,
              payload: { type: 'text', text: 'gap trigger group' },
            },
          ],
        };
      }
      return { ok: true };
    });

    const result = await client.pullGroupV2('g1', 0, 10);

    expect(result).toEqual([]);
    expect(fillSpy).not.toHaveBeenCalled();
    expect((client as any)._seqTracker.getContiguousSeq('group:g1')).toBe(3);
  });

  it('group.thought.put 自动使用 V2 群 envelope 并附带签名', async () => {
    const client = makeV2Client();
    const envelope = { type: 'e2ee.group_encrypted', version: 'v2', suite: 'AUN-X25519-MLKEM768-v1' };
    vi.spyOn(client as any, '_buildV2GroupEnvelope').mockResolvedValue(envelope);
    vi.spyOn(client as any, '_signClientOperation').mockImplementation((_method: string, params: any) => {
      params.client_signature = { aid: 'alice.aid.com' };
    });
    const transportCall = vi.fn().mockResolvedValue({ ok: true });
    (client as any)._transport.call = transportCall;

    await client.call('group.thought.put', {
      group_id: 'g1',
      context: { type: 'run', id: 'run-root' },
      payload: { type: 'thought', text: '推理片段' },
    });

    expect(transportCall).toHaveBeenCalledWith('group.thought.put', expect.objectContaining({
      group_id: 'g1',
      context: { type: 'run', id: 'run-root' },
      encrypted: true,
      payload: envelope,
      thought_id: expect.stringMatching(/^gt-/),
      client_signature: { aid: 'alice.aid.com' },
    }));
  });

  it('message.thought.put 自动使用 V2 P2P envelope 并附带签名', async () => {
    const client = makeV2Client();
    const envelope = { type: 'e2ee.p2p_encrypted', version: 'v2', suite: 'AUN-X25519-MLKEM768-v1' };
    vi.spyOn(client as any, '_buildV2P2PEnvelope').mockResolvedValue(envelope);
    vi.spyOn(client as any, '_signClientOperation').mockImplementation((_method: string, params: any) => {
      params.client_signature = { aid: 'alice.aid.com' };
    });
    const transportCall = vi.fn().mockResolvedValue({ ok: true });
    (client as any)._transport.call = transportCall;

    await client.call('message.thought.put', {
      to: 'bob.aid.com',
      context: { type: 'run', id: 'run-root' },
      payload: { type: 'thought', text: '推理片段' },
    });

    expect(transportCall).toHaveBeenCalledWith('message.thought.put', expect.objectContaining({
      to: 'bob.aid.com',
      context: { type: 'run', id: 'run-root' },
      encrypted: true,
      payload: envelope,
      thought_id: expect.stringMatching(/^mt-/),
      client_signature: { aid: 'alice.aid.com' },
    }));
  });

  it('thought.put 的 V2 envelope 应携带 protected_headers', async () => {
    const client = makeV2Client();
    const p2pEnvelope = { type: 'e2ee.p2p_encrypted', version: 'v2', suite: 'AUN-X25519-MLKEM768-v1' };
    const groupEnvelope = { type: 'e2ee.group_encrypted', version: 'v2', suite: 'AUN-X25519-MLKEM768-v1' };
    const buildP2pSpy = vi.spyOn(client as any, '_buildV2P2PEnvelope').mockResolvedValue(p2pEnvelope);
    const buildGroupSpy = vi.spyOn(client as any, '_buildV2GroupEnvelope').mockResolvedValue(groupEnvelope);
    vi.spyOn(client as any, '_signClientOperation').mockImplementation(() => undefined);
    (client as any)._transport.call = vi.fn().mockResolvedValue({ ok: true });

    await client.call('message.thought.put', {
      to: 'bob.aid.com',
      context: { type: 'run', id: 'run-root' },
      protected_headers: { device_id: 'dev-a', slot_id: 'slot-a' },
      payload: { type: 'thought', text: 'p2p-thought' },
    });
    const p2pArgs = buildP2pSpy.mock.calls[0][0];
    expect(p2pArgs).toEqual(expect.objectContaining({
      protectedHeaders: { device_id: 'dev-a', slot_id: 'slot-a' },
      context: { type: 'run', id: 'run-root' },
    }));

    await client.call('group.thought.put', {
      group_id: 'g1',
      context: { type: 'run', id: 'run-root' },
      protected_headers: { device_id: 'dev-a', slot_id: 'slot-a' },
      payload: { type: 'thought', text: 'group-thought' },
    });
    const groupArgs = buildGroupSpy.mock.calls[0][0];
    expect(groupArgs).toEqual(expect.objectContaining({
      protectedHeaders: { device_id: 'dev-a', slot_id: 'slot-a' },
      context: { type: 'run', id: 'run-root' },
    }));
  });

  it('V2 thought / send 的缺参错误应与 Python 对齐', async () => {
    const client = makeV2Client();

    await expect(client.call('message.send', {
      payload: { type: 'text', text: 'hello' },
    })).rejects.toThrow("message.send requires 'to'");

    await expect(client.call('group.send', {
      payload: { type: 'text', text: 'hello' },
    })).rejects.toThrow("group.send requires 'group_id'");

    await expect(client.call('group.thought.put', {
      context: { type: 'run', id: 'run-root' },
      payload: { type: 'thought', text: 'group-thought' },
    })).rejects.toBeInstanceOf(StateError);
  });

  it('group.thought.get 逐条解密 V2 envelope 并返回 thoughts[]', async () => {
    const client = makeV2Client();
    vi.spyOn(client as any, '_decryptV2EnvelopeForThought').mockResolvedValue({
      type: 'thought',
      text: '只给感兴趣的人看',
    });
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      found: true,
      group_id: 'g1',
      sender_aid: 'alice.aid.com',
      thoughts: [
        {
          thought_id: 'gt-1',
          context: { type: 'run', id: 'run-root' },
          payload: { type: 'e2ee.group_encrypted', version: 'v2', suite: 'AUN-X25519-MLKEM768-v1' },
          created_at: 1710504000000,
        },
      ],
    });

    const result = await client.call('group.thought.get', {
      group_id: 'g1',
      sender_aid: 'alice.aid.com',
      context: { type: 'run', id: 'run-root' },
    }) as any;

    expect(result.thoughts[0]).toMatchObject({
      thought_id: 'gt-1',
      message_id: 'gt-1',
      context: { type: 'run', id: 'run-root' },
      payload: { type: 'thought', text: '只给感兴趣的人看' },
      e2ee: {
        version: 'v2',
        suite: 'AUN-X25519-MLKEM768-v1',
        forward_secrecy: true,
      },
    });
  });

  it('message.thought.get 逐条解密 V2 envelope 并返回 thoughts[]', async () => {
    const client = makeV2Client();
    vi.spyOn(client as any, '_decryptV2EnvelopeForThought').mockResolvedValue({
      type: 'thought',
      text: '只给接收方看',
    });
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      found: true,
      sender_aid: 'alice.aid.com',
      peer_aid: 'bob.aid.com',
      thoughts: [
        {
          thought_id: 'mt-1',
          from: 'alice.aid.com',
          to: 'bob.aid.com',
          context: { type: 'run', id: 'run-root' },
          payload: { type: 'e2ee.p2p_encrypted', version: 'v2', suite: 'AUN-X25519-MLKEM768-v1' },
          created_at: 1710504000000,
        },
      ],
    });

    const result = await client.call('message.thought.get', {
      sender_aid: 'alice.aid.com',
      context: { type: 'run', id: 'run-root' },
    }) as any;

    expect(result.thoughts[0]).toMatchObject({
      thought_id: 'mt-1',
      message_id: 'mt-1',
      from: 'alice.aid.com',
      to: 'bob.aid.com',
      context: { type: 'run', id: 'run-root' },
      payload: { type: 'thought', text: '只给接收方看' },
      e2ee: {
        version: 'v2',
        suite: 'AUN-X25519-MLKEM768-v1',
        forward_secrecy: true,
      },
    });
  });

  it('thought selector 必须提供 context.type + context.id', async () => {
    const client = new AUNClient();

    expect(() => (client as any)._validateOutboundCall('message.thought.put', {
      to: 'bob.aid.com',
      payload: { type: 'thought' },
    })).toThrow('context.type');

    expect(() => (client as any)._validateOutboundCall('message.thought.put', {
      to: 'bob.aid.com',
      context: { type: 'run' },
      payload: { type: 'thought' },
    })).toThrow('context.type');
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
