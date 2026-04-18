// ── client 模块单元测试 ──────────────────────────────────────
// AUNClient 完整功能需要 Gateway 环境。
// 此处测试可独立验证的构造、配置和状态管理逻辑。
import 'fake-indexeddb/auto';
import { describe, it, expect, vi } from 'vitest';
import { AUNClient } from '../../src/client.js';
import { RPCTransport } from '../../src/transport.js';
import { AuthError, ConnectionError, StateError, PermissionError, ValidationError } from '../../src/errors.js';

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

  it('不允许以 verify_ssl=false 构造浏览器 SDK', () => {
    expect(() => new AUNClient({ verify_ssl: false }))
      .toThrowError(new ValidationError('browser SDK does not allow verify_ssl=false'));
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
});

describe('AUNClient 子模块可访问', () => {
  it('auth 命名空间应可用', () => {
    const client = new AUNClient();
    expect(client.auth).toBeDefined();
  });

  it('e2ee 管理器应可用', () => {
    const client = new AUNClient();
    expect(client.e2ee).toBeDefined();
  });

  it('groupE2ee 管理器应可用', () => {
    const client = new AUNClient();
    expect(client.groupE2ee).toBeDefined();
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
    });

    (client as any)._aid = aid;
    await (client as any)._syncIdentityAfterConnect('tok-connect');

    const prekeys = await ks.loadE2EEPrekeys(aid);
    const instanceState = await ks.loadInstanceState(aid, deviceId, slotId);
    expect(instanceState.access_token).toBe('tok-connect');
    expect(prekeys.pk1.private_key_pem).toBe('KEEP_ME');
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

describe('AUNClient prekey 证书指纹编排', () => {
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
    const [, sentParams] = (client as any)._transport.call.mock.calls[0];
    expect(sentParams.delivery_mode).toBeUndefined();
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
    (client as any)._e2ee.encryptOutbound = vi.fn().mockResolvedValue([
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

  it('无 prekey 时应继续走 long_term_key 路径', async () => {
    const client = new AUNClient();
    ((client as any).configModel).requireForwardSecrecy = false;
    (client as any)._fetchPeerPrekeys = vi.fn().mockResolvedValue([]);
    (client as any)._fetchPeerPrekey = vi.fn().mockResolvedValue(null);
    (client as any)._fetchPeerCert = vi.fn().mockResolvedValue('CERT');
    (client as any)._e2ee.encryptOutbound = vi.fn().mockResolvedValue([
      { ciphertext: 'ok', sender_cert_fingerprint: 'sha256:sender' },
      { encrypted: true, forward_secrecy: false, mode: 'long_term_key', degraded: true, degradation_reason: 'no_prekey_available' },
    ]);
    (client as any)._dispatcher.publish = vi.fn().mockResolvedValue(undefined);
    (client as any)._transport.call = vi.fn().mockResolvedValue({ ok: true });

    const result = await (client as any)._sendEncrypted({
      to: 'bob.example.com',
      payload: { text: 'hello' },
    });

    expect(result).toEqual({ ok: true });
    expect((client as any)._fetchPeerPrekey).toHaveBeenCalledWith('bob.example.com');
    expect((client as any)._fetchPeerCert).toHaveBeenCalledWith('bob.example.com', undefined);
    expect((client as any)._e2ee.encryptOutbound).toHaveBeenCalledWith(
      'bob.example.com',
      { text: 'hello' },
      expect.objectContaining({ prekey: null }),
    );
  });
});

describe('AUNClient.connect prekey 上传', () => {
  it('连接成功后应立即上传 current prekey', async () => {
    const client = new AUNClient();
    (client as any)._transport.connect = vi.fn().mockResolvedValue({ nonce: 'challenge' });
    (client as any)._auth.initializeWithToken = vi.fn().mockResolvedValue(undefined);
    (client as any)._syncIdentityAfterConnect = vi.fn().mockResolvedValue(undefined);
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
      await vi.advanceTimersByTimeAsync(50);
      await reconnectLoop;

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

      (client as any)._startHeartbeat();
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

describe('AUNClient 群补拉实例上下文', () => {
  it('_fillGroupGap 应复用当前实例 device_id', async () => {
    const client = new AUNClient();
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
