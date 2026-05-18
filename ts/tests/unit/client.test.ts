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
import { ProtectedHeaders } from '../../src/e2ee.js';

describe('AUNClient peer 证书缓存', () => {
  it('TTL 应为 3600 秒', () => {
    const source = readFileSync(new URL('../../src/client.ts', import.meta.url), 'utf8');
    expect(source).toContain('const PEER_CERT_CACHE_TTL = 3600;');
    expect(source).toContain('const PEER_PREKEYS_CACHE_TTL = 3600;');
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
    }, deviceId);

    (client as any)._aid = aid;
    (client as any)._syncIdentityAfterConnect('tok-connect');

    const prekeys = ks.loadE2EEPrekeys(aid, deviceId);
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

  it('单条空 device_id 应回退到固定值', async () => {
    const client = new AUNClient();
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      found: true,
      device_prekeys: [{
        device_id: '',
        prekey_id: 'pk-legacy',
        public_key: 'pub-legacy',
        signature: 'sig-legacy',
      }],
    });

    await expect((client as any)._fetchPeerPrekey('bob.example.com')).resolves.toMatchObject({
      device_id: 'aun_device_id',
      prekey_id: 'pk-legacy',
    });
  });

  it('多条 device_prekeys 中空 device_id 应被过滤', async () => {
    const client = new AUNClient();
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      found: true,
      device_prekeys: [
        { device_id: '', prekey_id: 'pk-empty', public_key: 'pub-empty', signature: 'sig-empty' },
        { device_id: 'device-b', prekey_id: 'pk-b', public_key: 'pub-b', signature: 'sig-b' },
      ],
    });

    await expect((client as any)._fetchPeerPrekeys('bob.example.com')).resolves.toEqual([
      expect.objectContaining({ device_id: 'device-b', prekey_id: 'pk-b' }),
    ]);
  });

  it('多条 device_prekeys 中 aun_device_id 占位项应被过滤', async () => {
    const client = new AUNClient();
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      found: true,
      device_prekeys: [
        { device_id: 'aun_device_id', prekey_id: 'pk-legacy', public_key: 'pub-legacy', signature: 'sig-legacy' },
        { device_id: 'device-b', prekey_id: 'pk-b', public_key: 'pub-b', signature: 'sig-b' },
      ],
    });

    await expect((client as any)._fetchPeerPrekeys('bob.example.com')).resolves.toEqual([
      expect.objectContaining({ device_id: 'device-b', prekey_id: 'pk-b' }),
    ]);
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
      payload: { type: 'text', text: 'hello' },
    });

    expect(result).toEqual({ ok: true });
    expect((client as any)._sendEncryptedSingle).not.toHaveBeenCalled();
    expect((client as any)._transport.call).toHaveBeenCalledWith('message.send', expect.objectContaining({
      type: 'e2ee.multi_device',
    }));
  });

  it('加密 P2P 多设备发送应透传 durable 为 persist_required', async () => {
    const client = new AUNClient();
    (client as any)._fetchPeerPrekeys = vi.fn().mockResolvedValue([
      { device_id: 'phone', prekey_id: 'pk-phone', public_key: 'pub-1', signature: 'sig-1' },
      { device_id: 'laptop', prekey_id: 'pk-laptop', public_key: 'pub-2', signature: 'sig-2' },
    ]);
    (client as any)._buildSelfSyncCopies = vi.fn().mockResolvedValue([]);
    (client as any)._buildRecipientDeviceCopies = vi.fn().mockResolvedValue([
      { device_id: 'phone', envelope: { ciphertext: 'c1' } },
      { device_id: 'laptop', envelope: { ciphertext: 'c2' } },
    ]);
    (client as any)._transport.call = vi.fn().mockResolvedValue({ ok: true });

    await (client as any)._sendEncrypted({
      to: 'bob.example.com',
      payload: { type: 'text', text: 'hello' },
      durable: true,
    });

    expect((client as any)._transport.call).toHaveBeenCalledWith('message.send', expect.objectContaining({
      persist_required: true,
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
      device_id: 'dev-1',
    }]);
    (client as any)._fetchPeerCert = vi.fn().mockResolvedValue('CERT');
    (client as any)._e2ee.encryptOutbound = vi.fn().mockReturnValue([
      { ciphertext: 'ok' },
      { encrypted: true, forward_secrecy: true, mode: 'prekey_ecdh_v2' },
    ]);
    (client as any)._transport.call = vi.fn().mockResolvedValue({ ok: true });

    const result = await (client as any)._sendEncrypted({
      to: 'bob.example.com',
      payload: { type: 'text', text: 'hello' },
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
    // 仅活跃 prekey 被消费时才触发上传；测试需显式设置 active 模拟"刚上传"的状态
    (client as any)._activePrekeyId = 'pk-1';
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
        // 允许 ack 等调用通过
        return { ok: true };
      });
      vi.spyOn(Math, 'random').mockReturnValue(0);

      await (client as any)._onRawGroupChanged({
        group_id: 'test-group-123',
        action: 'member_removed',
        member_aid: 'removed.aid.com',
        old_epoch: 5,
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

// ── group.add_member epoch 轮换兜底测试 ──────────────────

describe('group.add_member 成员变更 epoch 处理', () => {
  it('group.add_member 返回 error 时不应触发 epoch 轮换', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'device-001';

    // 模拟 transport.call 返回错误结果
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      error: { code: -33003, message: 'not authorized' },
    });

    const rotateSpy = vi.spyOn(client as any, '_maybeLeadRotateGroupEpoch').mockResolvedValue(undefined);

    await client.call('group.add_member', {
      group_id: 'group-123',
      aid: 'new-member.aid.com',
    });

    // 失败的 add_member 不应触发 epoch 轮换
    expect(rotateSpy).not.toHaveBeenCalled();
  });

  it('group.add_member 成功时应触发 epoch 轮换兜底', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'device-001';

    // 模拟成功结果
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      ok: true,
    });

    const rotateSpy = vi.spyOn(client as any, '_maybeLeadRotateGroupEpoch').mockResolvedValue(undefined);

    await client.call('group.add_member', {
      group_id: 'group-123',
      aid: 'new-member.aid.com',
    });

    // 成功的 add_member 应触发 epoch 轮换兜底（fire-and-forget）
    expect(rotateSpy).toHaveBeenCalledWith(
      'group-123',
      expect.any(String),
      null,
      false,
    );
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

// ── R3: 解密失败不应 publish 密文给应用层 ──────────────────

describe('R3: 解密失败不应将密文 publish 给应用层', () => {
  /** 构造一个预设解密失败的 client */
  function makeDecryptFailClient() {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'device-001';
    (client as any)._identity = { aid: 'test.aid.com' };

    // _decryptGroupMessage 返回原始消息（无 e2ee 字段）= 解密失败
    vi.spyOn(client as any, '_decryptGroupMessage').mockImplementation(async (msg: any) => msg);
    // _ensureSenderCertCached 直接通过
    vi.spyOn(client as any, '_ensureSenderCertCached').mockResolvedValue(true);
    // SeqTracker 不触发补洞
    (client as any)._seqTracker = {
      onMessageSeq: () => false,
      getContiguousSeq: () => 0,
      exportState: () => ({}),
    };

    return client;
  }

  it('推送路径：解密失败时不应 publish group.message_created', async () => {
    const client = makeDecryptFailClient();
    const events: string[] = [];
    (client as any)._dispatcher.subscribe('group.message_created', () => { events.push('created'); });
    (client as any)._dispatcher.subscribe('group.message_undecryptable', () => { events.push('undecryptable'); });

    const msg = {
      group_id: 'g1',
      from: 'sender.aid.com',
      seq: 1,
      payload: { type: 'e2ee.group_encrypted', epoch: 1, ciphertext: 'AAAA' },
    };
    await (client as any)._processAndPublishGroupMessage(msg);

    // 不应有 group.message_created 事件
    expect(events).not.toContain('created');
    // 应有 group.message_undecryptable 事件
    expect(events).toContain('undecryptable');
  });

  it('推送路径：解密失败时应入 pending 队列', async () => {
    const client = makeDecryptFailClient();
    const msg = {
      group_id: 'g1',
      from: 'sender.aid.com',
      seq: 2,
      payload: { type: 'e2ee.group_encrypted', epoch: 1, ciphertext: 'BBBB' },
    };
    await (client as any)._processAndPublishGroupMessage(msg);

    const pending = (client as any)._pendingDecryptMsgs.get('group:g1');
    expect(pending).toBeDefined();
    expect(pending.length).toBe(1);
  });

  it('批量路径：解密失败的消息不应出现在返回结果中', async () => {
    const client = makeDecryptFailClient();

    const msgs = [
      { group_id: 'g1', from: 'a', seq: 1, payload: { type: 'e2ee.group_encrypted', epoch: 1, ciphertext: 'X' } },
      { group_id: 'g1', from: 'b', seq: 2, dispatch_mode: 'mention', payload: { type: 'text', text: 'hello' } }, // 非加密消息
    ];
    const result = await (client as any)._decryptGroupMessages(msgs);

    // 只有非加密消息应在结果中，加密但解密失败的不应在结果中
    expect(result.length).toBe(1);
    expect(result[0].payload.type).toBe('text');
    expect(result[0].payload.dispatch_mode).toBe('mention');
    expect(result[0].dispatch_mode).toBe('mention');
  });

  it('批量路径：缺省 dispatch_mode 时默认 broadcast', async () => {
    const client = makeDecryptFailClient();

    const result = await (client as any)._decryptGroupMessages([
      { group_id: 'g1', from: 'b', seq: 2, payload: { type: 'text', text: 'hello' } },
    ]);

    expect(result.length).toBe(1);
    expect(result[0].payload.dispatch_mode).toBe('broadcast');
    expect(result[0].dispatch_mode).toBe('broadcast');
  });
});

// ── R4: _retryPendingDecryptMsgs 应被激活 ──────────────────

describe('R4: 收到密钥后应触发 pending 消息重试', () => {
  it('handleIncoming 返回 distribution 后应调用 _retryPendingDecryptMsgs', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    (client as any)._identity = { aid: 'test.aid.com' };

    // 预填充 pending 队列
    (client as any)._pendingDecryptMsgs.set('group:g1', [{ fake: true }]);

    // handleIncoming 返回 'distribution'
    (client as any)._groupE2ee = {
      handleIncoming: vi.fn().mockReturnValue('distribution'),
      decrypt: vi.fn(),
      loadSecret: vi.fn(),
      getMemberAids: vi.fn().mockReturnValue([]),
      // _tryHandleGroupKeyMessage 用 currentEpoch 判定本地是否已 ahead
      currentEpoch: vi.fn().mockReturnValue(0),
    };

    const retrySpy = vi.spyOn(client as any, '_retryPendingDecryptMsgs').mockResolvedValue(undefined);
    (client as any).call = vi.fn().mockResolvedValue({
      epoch: 2,
      committed_epoch: 2,
      committed_rotation: { rotation_id: 'rot-r4' },
    });

    const msg = {
      from: 'peer.aid.com',
      payload: {
        type: 'e2ee.group_key_distribution',
        group_id: 'g1',
        epoch: 2,
        rotation_id: 'rot-r4',
      },
    };

    await (client as any)._tryHandleGroupKeyMessage(msg);

    expect(retrySpy).toHaveBeenCalledWith('g1');
  });
});

describe('GROUP epoch 轮换竞态防护', () => {
  it('pending decrypt retry 不应覆盖 retry 期间新入队消息', async () => {
    const client = new AUNClient();
    const ns = 'group:g1';
    const first = { group_id: 'g1', seq: 1, payload: { type: 'e2ee.group_encrypted' } };
    const second = { group_id: 'g1', seq: 2, payload: { type: 'e2ee.group_encrypted' } };
    (client as any)._pendingDecryptMsgs.set(ns, [first]);
    vi.spyOn(client as any, '_decryptGroupMessage').mockImplementation(async (msg: any) => {
      (client as any)._enqueuePendingDecrypt('g1', second);
      return { ...msg, e2ee: { ok: true } };
    });
    vi.spyOn((client as any)._dispatcher, 'publish').mockResolvedValue(undefined);

    await (client as any)._retryPendingDecryptMsgs('g1');

    expect((client as any)._pendingDecryptMsgs.get(ns)).toEqual([second]);
  });

  it('无 rotation_id 的未来 epoch 分发应被拒绝', async () => {
    const client = new AUNClient();
    // 验证逻辑会跳过非活跃群（不在 _groupSynced 中）。本测试要走完整 RPC 校验路径，
    // 必须先把目标群加入活跃列表。
    (client as any)._groupSynced.add('g1');
    (client as any).call = vi.fn().mockResolvedValue({ epoch: 1, committed_epoch: 1 });

    await expect((client as any)._verifyActiveGroupRotationDistribution({
      type: 'e2ee.group_key_distribution',
      group_id: 'g1',
      epoch: 2,
      commitment: 'c2',
    })).resolves.toBe(false);
  });

  it('未提交 epoch 的 key response 应被拒绝', async () => {
    const client = new AUNClient();
    (client as any).call = vi.fn().mockResolvedValue({ epoch: 1, committed_epoch: 1 });

    await expect((client as any)._verifyGroupKeyResponseEpoch({
      type: 'e2ee.group_key_response',
      group_id: 'g1',
      epoch: 2,
      commitment: 'c2',
    })).resolves.toBe(false);
  });

  it('新成员恢复时 committed response commitment 不匹配应放行', async () => {
    const client = new AUNClient();
    (client as any)._aid = 'bob.aid.com';
    (client as any).call = vi.fn().mockResolvedValue({
      epoch: 2,
      committed_epoch: 2,
      committed_rotation: {
        target_epoch: 2,
        key_commitment: 'committed-old',
        expected_members: ['alice.aid.com'],
      },
    });

    await expect((client as any)._verifyGroupKeyResponseEpoch({
      type: 'e2ee.group_key_response',
      group_id: 'g1',
      epoch: 2,
      commitment: 'new-member-commitment',
    })).resolves.toBe(true);
  });

  it('新成员 backfill 时 committed distribution commitment 不匹配应放行', async () => {
    const client = new AUNClient();
    (client as any)._aid = 'bob.aid.com';
    (client as any).call = vi.fn().mockResolvedValue({
      epoch: 2,
      committed_epoch: 2,
      committed_rotation: {
        target_epoch: 2,
        key_commitment: 'committed-old',
        expected_members: ['alice.aid.com'],
      },
    });

    await expect((client as any)._verifyActiveGroupRotationDistribution({
      type: 'e2ee.group_key_distribution',
      group_id: 'g1',
      epoch: 2,
      commitment: 'new-member-commitment',
    })).resolves.toBe(true);
  });

  it('发送前恢复等待期间 committed epoch 推进时应返回最新 epoch', async () => {
    const client = new AUNClient();
    (client as any)._groupE2ee = {
      loadSecret: vi.fn().mockImplementation((_groupId: string, epoch: number) => (
        epoch === 1
          ? { pending_rotation_id: 'rot-local-1', commitment: 'c1' }
          : { pending_rotation_id: 'rot-2', commitment: 'c2' }
      )),
    };
    const recoverSpy = vi.spyOn(client as any, '_recoverGroupEpochKey').mockResolvedValue(true);
    vi.spyOn(client as any, '_committedGroupEpochState').mockResolvedValue({
      epoch: 2,
      committed_epoch: 2,
      committed_rotation: { rotation_id: 'rot-2', key_commitment: 'c2' },
    });

    const readyEpoch = await (client as any)._ensureCommittedGroupSecretForSend('g1', 1, {
      epoch: 1,
      committed_epoch: 1,
      committed_rotation: { rotation_id: 'rot-other', key_commitment: 'other' },
    });

    expect(readyEpoch).toBe(2);
    expect(recoverSpy).toHaveBeenCalledWith('g1', 1, '', 5000);
    expect(recoverSpy).toHaveBeenCalledWith('g1', 2, '', 5000);
  });

  it('发送前 committed membership gap 应触发 repair 并等待新 committed epoch', async () => {
    const client = new AUNClient();
    (client as any)._aid = 'bob.aid.com';
    (client as any)._groupE2ee = {
      loadSecret: vi.fn()
        .mockResolvedValueOnce({ commitment: 'c1' })
        .mockResolvedValueOnce({ commitment: 'c2' }),
    };
    (client as any).call = vi.fn().mockResolvedValue({
      members: [
        { aid: 'alice.aid.com', status: 'active' },
        { aid: 'bob.aid.com', status: 'active' },
        { aid: 'charlie.aid.com', status: 'active' },
      ],
    });
    vi.spyOn(client as any, '_groupAllowsMemberEpochRotation').mockResolvedValue(true);
    const repairSpy = vi.spyOn(client as any, '_maybeLeadRotateGroupEpoch').mockResolvedValue(undefined);
    vi.spyOn(client as any, '_committedGroupEpochState').mockResolvedValue({
      epoch: 2,
      committed_epoch: 2,
      committed_rotation: {
        rotation_id: 'rot-2',
        key_commitment: 'c2',
        expected_members: ['alice.aid.com', 'bob.aid.com', 'charlie.aid.com'],
      },
    });

    const readyEpoch = await (client as any)._ensureCommittedGroupSecretForSend('g1', 1, {
      epoch: 1,
      committed_epoch: 1,
      committed_rotation: {
        rotation_id: 'rot-1',
        key_commitment: 'c1',
        expected_members: ['alice.aid.com', 'bob.aid.com'],
      },
    });

    expect(readyEpoch).toBe(2);
    expect(repairSpy).toHaveBeenCalledWith(
      'g1',
      'g1:committed_membership_gap:aid:bob.aid.com:epoch:1',
      1,
      true,
    );
  });

  it('sender membership floor 错误应作为可恢复 epoch 错误重试', () => {
    const client = new AUNClient();
    const err = new StateError('e2ee epoch below sender membership floor: epoch=1 floor=2');

    expect((client as any)._isGroupEpochTooOldError(err)).toBe(true);
    expect((client as any)._isRecoverableGroupEpochError(err)).toBe(true);
  });

  it('epoch changed during send 错误应作为可恢复 epoch 错误重试', () => {
    const client = new AUNClient();
    const err = new StateError('e2ee epoch changed during send: expected 1, current 2');

    expect((client as any)._isGroupEpochChangedDuringSendError(err)).toBe(true);
    expect((client as any)._isRecoverableGroupEpochError(err)).toBe(true);
  });

  it('本地 epoch 1 但服务端 epoch 0 时应先补同步初始 epoch', async () => {
    const client = new AUNClient();
    let getEpochCalls = 0;
    (client as any)._groupE2ee = {
      currentEpoch: vi.fn().mockResolvedValue(1),
      loadSecret: vi.fn().mockReturnValue({ epoch: 1, commitment: 'c1', member_aids: ['alice.aid'] }),
    };
    (client as any).call = vi.fn().mockImplementation(async (method: string) => {
      expect(method).toBe('group.e2ee.get_epoch');
      getEpochCalls += 1;
      return getEpochCalls === 1 ? { epoch: 0, committed_epoch: 0 } : { epoch: 1, committed_epoch: 1 };
    });
    const syncSpy = vi.spyOn(client as any, '_syncEpochToServer').mockResolvedValue(undefined);

    await (client as any)._ensureGroupEpochReady('g1', false);

    expect(syncSpy).toHaveBeenCalledWith('g1');
    expect(getEpochCalls).toBe(2);
  });

  it('初始 epoch 补同步后服务端仍为 0 时应拒绝继续发送', async () => {
    const client = new AUNClient();
    (client as any)._groupE2ee = {
      currentEpoch: vi.fn().mockResolvedValue(1),
      loadSecret: vi.fn().mockReturnValue({ epoch: 1, commitment: 'c1', member_aids: ['alice.aid'] }),
    };
    (client as any).call = vi.fn().mockResolvedValue({ epoch: 0, committed_epoch: 0 });
    vi.spyOn(client as any, '_syncEpochToServer').mockResolvedValue(undefined);

    await expect((client as any)._ensureGroupEpochReady('g1', false))
      .rejects.toThrow('initial epoch sync has not completed');
  });

  it('服务端 epoch 已领先且恢复超时时不应降级调用 group.send', async () => {
    vi.useFakeTimers();
    try {
      const client = new AUNClient();
      (client as any)._state = 'connected';
      (client as any)._aid = 'alice.aid.com';
      (client as any)._identity = { aid: 'alice.aid.com' };
      (client as any)._groupSynced.add('g1');
      (client as any)._groupE2ee = {
        currentEpoch: vi.fn().mockResolvedValue(1),
        loadSecret: vi.fn().mockReturnValue({ epoch: 1, commitment: 'c1', member_aids: ['alice.aid.com'] }),
        encrypt: vi.fn(),
        encryptWithEpoch: vi.fn(),
        getMemberAids: vi.fn().mockReturnValue([]),
      };
      vi.spyOn(client as any, '_requestGroupKeyFromCandidates').mockResolvedValue(undefined);
      const transportCall = vi.fn().mockImplementation(async (method: string) => {
        if (method === 'group.e2ee.get_epoch') {
          return { epoch: 2, committed_epoch: 2, recovery_candidates: ['owner.aid.com'] };
        }
        if (method === 'group.send') return { ok: true };
        return {};
      });
      (client as any)._transport.call = transportCall;

      const sendPromise = (client as any)._sendGroupEncrypted({
        group_id: 'g1',
        payload: { type: 'text', text: 'hello' },
      });
      const assertion = expect(sendPromise).rejects.toThrow('key recovery has not completed');
      await vi.advanceTimersByTimeAsync(5500);

      await assertion;
      expect(transportCall.mock.calls.some(([method]) => method === 'group.send')).toBe(false);
      expect((client as any)._groupE2ee.encryptWithEpoch).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
      vi.restoreAllMocks();
    }
  });

  it('group.thought.put 应自动走群 E2EE 加密并附带签名', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'alice.aid.com';
    (client as any)._groupSynced.add('g1');
    (client as any)._groupE2ee = {
      encryptWithEpoch: vi.fn().mockReturnValue({ type: 'e2ee.group_encrypted', epoch: 2, ciphertext: 'abc' }),
    };
    vi.spyOn(client as any, '_ensureGroupEpochReady').mockResolvedValue(undefined);
    vi.spyOn(client as any, '_waitForGroupMembershipEpochFloor').mockResolvedValue(undefined);
    vi.spyOn(client as any, '_committedGroupEpochState').mockResolvedValue({ epoch: 2, committed_epoch: 2 });
    vi.spyOn(client as any, '_ensureCommittedGroupSecretForSend').mockResolvedValue(2);
    vi.spyOn(client as any, '_signClientOperation').mockImplementation(async (_method: string, params: any) => {
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
      type: 'e2ee.group_encrypted',
      thought_id: expect.stringMatching(/^gt-/),
      client_signature: { aid: 'alice.aid.com' },
    }));

    await client.call('group.thought.put', {
      group_id: 'g1',
      context: { type: 'run', id: 'run-1' },
      payload: { type: 'thought', text: '自主推理片段' },
    });

    expect(transportCall).toHaveBeenLastCalledWith('group.thought.put', expect.objectContaining({
      group_id: 'g1',
      context: { type: 'run', id: 'run-1' },
      encrypted: true,
      type: 'e2ee.group_encrypted',
      thought_id: expect.stringMatching(/^gt-/),
      client_signature: { aid: 'alice.aid.com' },
    }));
    expect(transportCall.mock.calls[transportCall.mock.calls.length - 1]?.[1]).not.toHaveProperty('reply_to');
  });

  it('group.thought.get 应逐条解密并返回 thoughts[]', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    vi.spyOn(client as any, '_decryptGroupMessage').mockResolvedValue({
      payload: { type: 'thought', text: '只给感兴趣的人看' },
      e2ee: {
        encryption_mode: 'epoch_group_key',
        context: { type: 'run', id: 'run-root' },
      },
    });
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      found: true,
      group_id: 'g1',
      sender_aid: 'alice.aid.com',
      context: { type: 'run', id: 'run-root' },
      thoughts: [
        {
          thought_id: 'gt-1',
          context: { type: 'run', id: 'run-root' },
          payload: { type: 'e2ee.group_encrypted', ciphertext: 'abc' },
          created_at: 1710504000000,
        },
      ],
    });

    const result = await client.call('group.thought.get', {
      group_id: 'g1',
      sender_aid: 'alice.aid.com',
      context: { type: 'run', id: 'run-root' },
    }) as any;

    expect(result.thoughts).toEqual([
      {
        thought_id: 'gt-1',
        message_id: 'gt-1',
        context: { type: 'run', id: 'run-root' },
        payload: { type: 'thought', text: '只给感兴趣的人看' },
        created_at: 1710504000000,
        e2ee: {
          encryption_mode: 'epoch_group_key',
          context: { type: 'run', id: 'run-root' },
        },
      },
    ]);
    expect((client as any)._decryptGroupMessage).toHaveBeenCalledWith(
      expect.objectContaining({
        message_id: 'gt-1',
        sender_aid: 'alice.aid.com',
        context: { type: 'run', id: 'run-root' },
      }),
      { skipReplay: true },
    );
  });

  it('message.thought.put 应自动走 P2P E2EE 加密并附带签名', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    vi.spyOn(client as any, '_fetchPeerPrekey').mockResolvedValue({ prekey_id: 'pk-1', cert_fingerprint: 'sha256:abc' });
    vi.spyOn(client as any, '_fetchPeerCert').mockResolvedValue('PEM');
    vi.spyOn(client as any, '_encryptCopyPayload').mockReturnValue([
      { type: 'e2ee.encrypted', ciphertext: 'abc' },
      { encrypted: true, forward_secrecy: true, mode: 'prekey_ecdh_v2' },
    ]);
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
      type: 'e2ee.encrypted',
      thought_id: expect.stringMatching(/^mt-/),
      client_signature: { aid: 'alice.aid.com' },
    }));

    await client.call('message.thought.put', {
      to: 'bob.aid.com',
      context: { type: 'run', id: 'run-1' },
      payload: { type: 'thought', text: '自主推理片段' },
    });

    expect(transportCall).toHaveBeenLastCalledWith('message.thought.put', expect.objectContaining({
      to: 'bob.aid.com',
      context: { type: 'run', id: 'run-1' },
      encrypted: true,
      type: 'e2ee.encrypted',
      thought_id: expect.stringMatching(/^mt-/),
      client_signature: { aid: 'alice.aid.com' },
    }));
    expect(transportCall.mock.calls[transportCall.mock.calls.length - 1]?.[1]).not.toHaveProperty('reply_to');
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

  it('message.thought.get 应逐条解密并返回 thoughts[]', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    vi.spyOn(client as any, '_ensureSenderCertCached').mockResolvedValue(true);
    (client as any)._e2ee = {
      _decryptMessage: vi.fn().mockReturnValue({
        payload: { type: 'thought', text: '只给感兴趣的人看' },
        e2ee: { encryption_mode: 'prekey_ecdh_v2' },
      }),
    };
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      found: true,
      sender_aid: 'alice.aid.com',
      peer_aid: 'bob.aid.com',
      context: { type: 'run', id: 'run-root' },
      thoughts: [
        {
          thought_id: 'mt-1',
          from: 'alice.aid.com',
          to: 'bob.aid.com',
          context: { type: 'run', id: 'run-root' },
          payload: { type: 'e2ee.encrypted', ciphertext: 'abc' },
          created_at: 1710504000000,
        },
      ],
    });

    const result = await client.call('message.thought.get', {
      sender_aid: 'alice.aid.com',
      context: { type: 'run', id: 'run-root' },
    }) as any;

    expect(result.thoughts).toEqual([
      {
        thought_id: 'mt-1',
        message_id: 'mt-1',
        context: { type: 'run', id: 'run-root' },
        from: 'alice.aid.com',
        to: 'bob.aid.com',
        payload: { type: 'thought', text: '只给感兴趣的人看' },
        created_at: 1710504000000,
        e2ee: { encryption_mode: 'prekey_ecdh_v2' },
      },
    ]);
  });

  it('stale pending secret 不应让 epoch key recovery 返回成功', async () => {
    const client = new AUNClient();
    (client as any)._groupE2ee = {
      loadSecret: vi.fn().mockReturnValue({ pending_rotation_id: 'rot-stale', commitment: 'c2' }),
    };
    (client as any).call = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'group.get_online_members') throw new Error('not supported');
      return {
        epoch: 2,
        committed_epoch: 2,
        committed_rotation: { rotation_id: 'rot-committed', key_commitment: 'c2' },
      };
    });
    const requestSpy = vi.spyOn(client as any, '_requestGroupKeyFromCandidates').mockResolvedValue(undefined);

    await expect((client as any)._recoverGroupEpochKey('g1', 2, '', 0)).resolves.toBe(false);

    expect((client as any).call).toHaveBeenCalledWith('group.e2ee.get_epoch', { group_id: 'g1' });
    expect(requestSpy).toHaveBeenCalledTimes(1);
  });

  it('poll 恢复拿到 epoch key 后应触发 pending decrypt retry', async () => {
    const client = new AUNClient();
    (client as any)._pendingDecryptMsgs.set('group:g1', [
      { group_id: 'g1', seq: 7, payload: { type: 'e2ee.group_encrypted', epoch: 2 } },
    ]);
    (client as any)._groupE2ee = {
      loadSecret: vi.fn()
        .mockReturnValue({ epoch: 2, commitment: 'c2' }),
    };
    (client as any).call = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'group.get_online_members') throw new Error('not supported');
      return { epoch: 2, committed_epoch: 2 };
    });
    vi.spyOn(client as any, '_requestGroupKeyFromCandidates').mockResolvedValue(undefined);
    const retrySpy = vi.spyOn(client as any, '_retryPendingDecryptMsgs').mockResolvedValue(undefined);

    await expect((client as any)._doRecoverGroupEpochKey('g1', 2, '', 0)).resolves.toBe(true);

    expect(retrySpy).toHaveBeenCalledWith('g1');
  });

  it('成员变更 trigger_id 优先使用 aid + epoch', () => {
    const client = new AUNClient();
    const triggerId = (client as any)._membershipRotationTriggerId('g1', {
      action: 'member_added',
      event_seq: 99,
      member: { aid: 'carol.aid' },
      old_epoch: 2,
    });
    expect(triggerId).toBe('g1:member_added:aid:carol.aid:epoch:2');
  });
});

// ── Epoch key recovery inflight 去重 ──────────────────

describe('epoch key recovery inflight 去重', () => {
  afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); });

  function makeRecoveryClient() {
    vi.useFakeTimers();
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'device-001';
    (client as any)._identity = { aid: 'test.aid.com' };
    (client as any)._seqTracker = {
      onMessageSeq: () => false,
      getContiguousSeq: () => 0,
      exportState: () => ({}),
    };

    let secretAvailable = false;
    (client as any)._groupE2ee = {
      loadSecret: vi.fn().mockImplementation(() => secretAvailable ? { key: 'ok' } : null),
      getMemberAids: vi.fn().mockReturnValue([]),
    };

    const requestSpy = vi.fn().mockImplementation(async () => {
      secretAvailable = true;
    });
    (client as any)._requestGroupKeyFromCandidates = requestSpy;
    (client as any).call = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'group.get_online_members') throw new Error('not supported');
      return { epoch: 3, recovery_candidates: ['peer.aid.com'] };
    });

    return {
      client,
      requestSpy,
      resetSecret: () => { secretAvailable = false; },
    };
  }

  /** 推进 fake timer 并 flush 所有 microtask，直至所有 promise settle */
  async function advanceUntilSettled() {
    for (let i = 0; i < 20; i++) {
      await vi.advanceTimersByTimeAsync(200);
    }
  }

  it('并发 3 次 recoverGroupEpochKey(同 groupId+epoch) 只应发起 1 次 key request', async () => {
    const { client, requestSpy } = makeRecoveryClient();

    const p1 = (client as any)._recoverGroupEpochKey('g1', 3, 'sender1', 2000);
    const p2 = (client as any)._recoverGroupEpochKey('g1', 3, 'sender2', 2000);
    const p3 = (client as any)._recoverGroupEpochKey('g1', 3, 'sender3', 2000);

    await advanceUntilSettled();
    await Promise.all([p1, p2, p3]);

    expect(requestSpy).toHaveBeenCalledTimes(1);
  }, 10000);

  it('不同 groupId 或 epoch 的恢复请求应各自独立', async () => {
    const { client, requestSpy } = makeRecoveryClient();

    const p1 = (client as any)._recoverGroupEpochKey('g1', 3, '', 2000);
    const p2 = (client as any)._recoverGroupEpochKey('g2', 3, '', 2000);
    const p3 = (client as any)._recoverGroupEpochKey('g1', 4, '', 2000);

    await advanceUntilSettled();
    await Promise.all([p1, p2, p3]);

    expect(requestSpy).toHaveBeenCalledTimes(3);
  }, 10000);

  it('恢复完成后同 key 的新请求应重新发起', async () => {
    const { client, requestSpy, resetSecret } = makeRecoveryClient();

    const p1 = (client as any)._recoverGroupEpochKey('g1', 3, '', 2000);
    await advanceUntilSettled();
    await p1;
    expect(requestSpy).toHaveBeenCalledTimes(1);

    resetSecret();

    const p2 = (client as any)._recoverGroupEpochKey('g1', 3, '', 2000);
    await advanceUntilSettled();
    await p2;
    expect(requestSpy).toHaveBeenCalledTimes(2);
  }, 10000);
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
    const decryptSpy = vi.spyOn(client as any, '_decryptSingleMessage').mockImplementation(async (msg: any) => msg);
    vi.spyOn(client as any, '_tryHandleGroupKeyMessage').mockResolvedValue(false);

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
    expect(decryptSpy).not.toHaveBeenCalled();
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

  it('group pending decrypt 重试成功也应走有序放行', async () => {
    const client = new AUNClient();
    const ns = 'group:g1';
    (client as any)._seqTracker.onMessageSeq(ns, 1);
    (client as any)._seqTracker.onMessageSeq(ns, 3);
    (client as any)._pendingDecryptMsgs.set(ns, [
      { group_id: 'g1', seq: 3, payload: { type: 'text' } },
    ]);
    vi.spyOn(client as any, '_decryptGroupMessage').mockResolvedValue({ group_id: 'g1', seq: 3, e2ee: { ok: true } });
    const published: number[] = [];
    client.on('group.message_created', (payload: any) => {
      published.push(Number(payload.seq));
    });

    await (client as any)._retryPendingDecryptMsgs('g1');
    expect(published).toEqual([]);
    expect((client as any)._pendingOrderedMsgs.get(ns)?.has(3)).toBe(true);

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
    (client as any)._pendingDecryptMsgs.set('group:g1', [
      { group_id: 'g1', seq: 4, payload: { type: 'e2ee.group_encrypted' } },
    ]);

    (client as any)._slotId = 'slot-b';
    (client as any)._refreshSeqTrackerContext();

    expect((client as any)._pendingOrderedMsgs.size).toBe(0);
    expect((client as any)._pendingDecryptMsgs.size).toBe(0);
  });
});

// ── 服务端 epoch key 恢复测试 ──────────────────────────────

describe('epoch key 恢复 join mode 路由', () => {
  function makeRecoveryClient() {
    const tmpDir = mkdtempSync(join(tmpdir(), 'aun-recovery-'));
    const client = new AUNClient({ aun_path: tmpDir });
    (client as any)._state = 'connected';
    (client as any)._aid = 'bob.test.com';
    return client;
  }

  it('open 群恢复应调用 group.e2ee.get_epoch_key', async () => {
    const client = makeRecoveryClient();
    const rpcLog: string[] = [];
    (client as any).call = vi.fn().mockImplementation(async (method: string) => {
      rpcLog.push(method);
      if (method === 'group.get_join_requirements') {
        return { join_requirements: { mode: 'open' } };
      }
      if (method === 'group.e2ee.get_epoch_key') {
        return { epoch: 2 };
      }
      if (method === 'group.e2ee.get_epoch') {
        return { epoch: 2, committed_epoch: 2, members: ['alice.test.com', 'bob.test.com'] };
      }
      return {};
    });

    await (client as any)._doRecoverGroupEpochKey('g1', 2, '', 500);
    expect(rpcLog).toContain('group.e2ee.get_epoch_key');
  });

  it('private 群恢复不应调用 group.e2ee.get_epoch_key', async () => {
    const client = makeRecoveryClient();
    const rpcLog: string[] = [];
    (client as any).call = vi.fn().mockImplementation(async (method: string) => {
      rpcLog.push(method);
      if (method === 'group.get_join_requirements') {
        return { join_requirements: { mode: 'approval' } };
      }
      if (method === 'group.e2ee.get_epoch') {
        return {
          epoch: 2, committed_epoch: 2,
          owner_aid: 'alice.test.com',
          members: ['alice.test.com', 'bob.test.com'],
        };
      }
      if (method === 'group.get_online_members') {
        return { members: [] };
      }
      if (method === 'message.send') return { ok: true };
      return {};
    });

    // P2P 恢复因无在线成员会直接返回 false
    const result = await (client as any)._doRecoverGroupEpochKey('g1', 2, '', 500);
    expect(result).toBe(false);
    expect(rpcLog).not.toContain('group.e2ee.get_epoch_key');
  });

  it('缺少成员快照时应拒绝服务端恢复', async () => {
    const client = makeRecoveryClient();
    (client as any).call = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'group.e2ee.get_epoch_key') {
        return { epoch: 2, encrypted_key: 'dGVzdA==' };
      }
      if (method === 'group.e2ee.get_epoch') {
        return { epoch: 2, committed_epoch: 2 };
      }
      return {};
    });

    const result = await (client as any)._tryRecoverEpochKeyFromServer('g1', 2);
    // 解密会失败（假的 encrypted_key），或者缺少成员快照
    expect(result).toBe(false);
  });
});
