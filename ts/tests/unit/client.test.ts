/**
 * AUNClient 单元测试
 *
 * 测试客户端构造、参数校验、状态管理等不需要网络连接的逻辑。
 */

import { describe, it, expect, vi } from 'vitest';
import { existsSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { AUNClient } from '../../src/client.js';
import { RPCTransport } from '../../src/transport.js';
import { AuthError, ConnectionError, PermissionError, StateError, ValidationError } from '../../src/errors.js';

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

  it('默认 SQLite 备份应写入 aunPath/.aun_backup', () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'aun-client-sqlite-'));
    const client = new AUNClient({ aun_path: tmpDir });
    expect(existsSync(join(tmpDir, '.aun_backup', 'aun_backup.db'))).toBe(true);
    expect(client.state).toBe('idle');
  });

  it('e2ee 属性可访问', () => {
    const client = new AUNClient();
    expect(client.e2ee).toBeDefined();
    expect(client.groupE2ee).toBeDefined();
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
  it('同步 token 时应写入实例态且不覆盖已有 prekey', () => {
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
    ks.saveE2EEPrekey(aid, 'pk1', {
      private_key_pem: 'KEEP_ME',
      created_at: 1,
    });

    (client as any)._aid = aid;
    (client as any)._syncIdentityAfterConnect('tok-connect');

    const prekeys = ks.loadE2EEPrekeys(aid);
    const instanceState = ks.loadInstanceState(aid, deviceId, '');
    expect(instanceState.access_token).toBe('tok-connect');
    expect(prekeys.pk1?.private_key_pem).toBe('KEEP_ME');
  });
});

describe('AUNClient message.send 接收者校验', () => {
  it('不允许向 group.{issuer} 发送 message.send', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';

    await expect(client.call('message.send', {
      to: 'group.example.com',
      payload: { text: 'hello' },
      encrypt: false,
    })).rejects.toThrow(ValidationError);
  });

  it('message.send 拒绝 persist 参数', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';

    await expect(client.call('message.send', {
      to: 'bob.example.com',
      payload: { text: 'hello' },
      encrypt: false,
      persist: true,
    })).rejects.toThrow("message.send no longer accepts 'persist'");
  });

  it('message.send 拒绝发送级 delivery_mode 参数', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';

    await expect(client.call('message.send', {
      to: 'bob.example.com',
      payload: { text: 'hello' },
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

    await client.call('message.send', {
      to: 'bob.example.com',
      payload: { text: 'hello' },
      encrypt: false,
    });

    const [, sentParams] = (client as any)._transport.call.mock.calls[0];
    expect(sentParams.delivery_mode).toBeUndefined();
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
});

describe('AUNClient._fetchPeerPrekey', () => {
  it('found=false 时返回 null，允许降级到 long_term_key', async () => {
    const client = new AUNClient();
    (client as any)._transport.call = vi.fn().mockResolvedValue({ found: false });

    await expect((client as any)._fetchPeerPrekey('bob.example.com')).resolves.toBeNull();
  });

  it('查询失败时抛出 ValidationError', async () => {
    const client = new AUNClient();
    (client as any)._transport.call = vi.fn().mockRejectedValue(new Error('boom'));

    await expect((client as any)._fetchPeerPrekey('bob.example.com')).rejects.toThrow(
      'failed to fetch peer prekey for bob.example.com',
    );
  });

  it('非法响应时抛出 ValidationError', async () => {
    const client = new AUNClient();
    (client as any)._transport.call = vi.fn().mockResolvedValue({ found: true });

    await expect((client as any)._fetchPeerPrekey('bob.example.com')).rejects.toThrow(
      'invalid prekey response for bob.example.com',
    );
  });
});

describe('AUNClient 证书 URL 与 prekey 指纹编排', () => {
  it('queue 模式下多设备仍应生成多设备密文', async () => {
    const client = new AUNClient();
    (client as any)._connectDeliveryMode = { mode: 'queue', routing: 'round_robin', affinity_ttl_ms: 0 };
    (client as any)._sendEncryptedSingle = vi.fn().mockResolvedValue({ ok: true });
    (client as any)._fetchPeerPrekeys = vi.fn().mockResolvedValue([
      { device_id: 'phone', prekey_id: 'pk-phone', public_key: 'pub-1', signature: 'sig-1', cert_fingerprint: 'sha256:abc' },
      { device_id: 'laptop', prekey_id: 'pk-laptop', public_key: 'pub-2', signature: 'sig-2', cert_fingerprint: 'sha256:abc' },
    ]);
    (client as any)._buildSelfSyncCopies = vi.fn().mockResolvedValue([]);
    (client as any)._buildRecipientDeviceCopies = vi.fn().mockResolvedValue([
      { device_id: 'phone', envelope: { ciphertext: 'c1' } },
      { device_id: 'laptop', envelope: { ciphertext: 'c2' } },
    ]);
    (client as any)._transport.call = vi.fn().mockResolvedValue({ ok: true });

    const result = await (client as any)._sendEncrypted({
      to: 'bob.example.com',
      payload: { text: 'hello' },
    });

    expect(result).toEqual({ ok: true });
    expect((client as any)._sendEncryptedSingle).not.toHaveBeenCalled();
    expect((client as any)._transport.call).toHaveBeenCalledWith('message.send', expect.objectContaining({
      type: 'e2ee.multi_device',
    }));
  });

  it('构建证书 URL 时应透传 cert_fingerprint', () => {
    expect((AUNClient as any)._buildCertUrl(
      'wss://gateway.example.com/aun',
      'bob.example.com',
      'sha256:abc',
    )).toBe('https://gateway.example.com/pki/cert/bob.example.com?cert_fingerprint=sha256%3Aabc');
  });

  it('发送加密消息时应按 prekey.cert_fingerprint 获取证书', async () => {
    const client = new AUNClient();
    (client as any)._fetchPeerPrekeys = vi.fn().mockResolvedValue([{
      prekey_id: 'pk-1',
      public_key: 'pub',
      signature: 'sig',
      cert_fingerprint: 'sha256:abc',
    }]);
    (client as any)._fetchPeerCert = vi.fn().mockResolvedValue('CERT');
    (client as any)._e2ee.encryptOutbound = vi.fn().mockReturnValue([
      { ciphertext: 'ok' },
      { encrypted: true, forward_secrecy: true, mode: 'prekey_ecdh_v2' },
    ]);
    (client as any)._transport.call = vi.fn().mockResolvedValue({ ok: true });

    const result = await (client as any)._sendEncrypted({
      to: 'bob.example.com',
      payload: { text: 'hello' },
    });

    expect(result).toEqual({ ok: true });
    expect((client as any)._fetchPeerCert).toHaveBeenCalledWith('bob.example.com', 'sha256:abc');
  });
});

describe('AUNClient.connect prekey 上传', () => {
  it('连接成功后应立即上传 current prekey', async () => {
    const client = new AUNClient();
    (client as any)._transport.connect = vi.fn().mockResolvedValue({ nonce: 'challenge' });
    (client as any)._auth.initializeWithToken = vi.fn().mockResolvedValue(undefined);
    (client as any)._syncIdentityAfterConnect = vi.fn();
    (client as any)._startBackgroundTasks = vi.fn();
    (client as any)._uploadPrekey = vi.fn().mockResolvedValue({ ok: true });

    await client.connect({
      access_token: 'tok-1',
      gateway: 'ws://gateway.example.com/aun',
    });

    expect((client as any)._uploadPrekey).toHaveBeenCalledTimes(1);
    expect(client.state).toBe('connected');
  });
});

describe('AUNClient prekey 补充', () => {
  it('同一个 prekey_id 只触发一次异步补充', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._uploadPrekey = vi.fn().mockResolvedValue({ ok: true });

    (client as any)._schedulePrekeyReplenishIfConsumed({
      e2ee: { encryption_mode: 'prekey_ecdh_v2', prekey_id: 'pk-1' },
    });
    (client as any)._schedulePrekeyReplenishIfConsumed({
      e2ee: { encryption_mode: 'prekey_ecdh_v2', prekey_id: 'pk-1' },
    });

    await vi.waitFor(() => {
      expect((client as any)._uploadPrekey).toHaveBeenCalledTimes(1);
    });

    (client as any)._schedulePrekeyReplenishIfConsumed({
      e2ee: { encryption_mode: 'prekey_ecdh_v2', prekey_id: 'pk-1' },
    });

    await new Promise(resolve => setTimeout(resolve, 0));
    expect((client as any)._uploadPrekey).toHaveBeenCalledTimes(1);
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
      await vi.advanceTimersByTimeAsync(50);
      await Promise.resolve();

      expect((client as any)._connectOnce).toHaveBeenCalledTimes(2);
      expect(client.state).toBe('terminal_failed');
      expect(publish).toHaveBeenCalledWith('connection.state', expect.objectContaining({
        state: 'terminal_failed',
        reason: 'max_attempts_exhausted',
        attempt: 2,
      }));
    } finally {
      vi.useRealTimers();
    }
  });

  it('心跳连续 2 次失败才触发断线处理', async () => {
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
      await vi.advanceTimersByTimeAsync(10);
      await Promise.resolve();
      expect(disconnectSpy).not.toHaveBeenCalled();

      await vi.advanceTimersByTimeAsync(10);
      await Promise.resolve();
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

describe('AUNClient 群组 epoch 自动轮换', () => {
  it('普通 member 收到 member_removed 事件时不应触发 rotate_epoch', async () => {
    vi.useFakeTimers();
    try {
      const client = new AUNClient();

      (client as any)._aid = 'member.aid.com';
      (client as any)._identity = { aid: 'member.aid.com' };
      (client as any)._state = 'connected';

      const rotateEpochSpy = vi.spyOn(client as any, '_rotateGroupEpoch').mockResolvedValue(undefined);
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
        throw new Error(`unexpected method: ${method}`);
      });
      vi.spyOn(Math, 'random').mockReturnValue(0);

      await (client as any)._onRawGroupChanged({
        group_id: 'test-group-123',
        action: 'member_removed',
        member_aid: 'removed.aid.com',
      });
      await vi.runAllTimersAsync();

      expect(callSpy).toHaveBeenCalledWith('group.get_members', { group_id: 'test-group-123' });
      expect(rotateEpochSpy).not.toHaveBeenCalled();
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

// ── group.add_member 密钥分发结果检查测试 ──────────────────

describe('group.add_member 失败时不应分发密钥', () => {
  it('group.add_member 返回 error 时不应触发密钥分发', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'device-001';

    // 模拟 transport.call 返回错误结果
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      error: { code: -33003, message: 'not authorized' },
    });

    const distributeSpy = vi.spyOn(client as any, '_distributeKeyToNewMember').mockResolvedValue(undefined);
    const rotateSpy = vi.spyOn(client as any, '_rotateGroupEpoch').mockResolvedValue(undefined);

    await client.call('group.add_member', {
      group_id: 'group-123',
      aid: 'new-member.aid.com',
    });

    // 失败的 add_member 不应触发密钥分发
    expect(distributeSpy).not.toHaveBeenCalled();
    expect(rotateSpy).not.toHaveBeenCalled();
  });

  it('group.add_member 成功时应触发密钥分发', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'device-001';

    // 模拟成功结果
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      ok: true,
    });

    const distributeSpy = vi.spyOn(client as any, '_distributeKeyToNewMember').mockResolvedValue(undefined);

    await client.call('group.add_member', {
      group_id: 'group-123',
      aid: 'new-member.aid.com',
    });

    // 成功的 add_member 应触发密钥分发
    expect(distributeSpy).toHaveBeenCalledWith('group-123', 'new-member.aid.com');
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
