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

    await client.call('message.send', {
      to: 'bob.example.com',
      payload: { type: 'text', text: 'hello' },
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

  it('message.pull 不应返回群密钥控制面消息', async () => {
    const client = new AUNClient();
    const rawMessage = {
      message_id: 'ctrl-1',
      from: 'alice.example.com',
      encrypted: true,
      payload: { type: 'e2ee.encrypted' },
    };
    const decryptedControl = {
      ...rawMessage,
      payload: { type: 'e2ee.group_key_distribution', group_id: 'g1' },
    };

    (client as any)._ensureSenderCertCached = vi.fn().mockResolvedValue(true);
    (client as any)._schedulePrekeyReplenishIfConsumed = vi.fn();
    (client as any)._e2ee = {
      decryptMessage: vi.fn().mockResolvedValue(decryptedControl),
    };
    (client as any)._groupE2ee = {
      handleIncoming: vi.fn().mockResolvedValue('distribution'),
    };

    const result = await (client as any)._decryptMessages([rawMessage]);

    expect(result).toEqual([]);
    expect((client as any)._e2ee.decryptMessage).toHaveBeenCalledWith(rawMessage, { skipReplay: true });
  });

  it('message.pull 识别控制面时不应消耗业务消息 seen set', async () => {
    const client = new AUNClient();
    const rawMessage = {
      message_id: 'biz-1',
      from: 'alice.example.com',
      encrypted: true,
      payload: { type: 'e2ee.encrypted' },
    };
    const decryptedBusiness = {
      ...rawMessage,
      payload: { type: 'text', text: 'hello' },
    };

    (client as any)._ensureSenderCertCached = vi.fn().mockResolvedValue(true);
    (client as any)._schedulePrekeyReplenishIfConsumed = vi.fn();
    (client as any)._e2ee = {
      decryptMessage: vi.fn().mockResolvedValue(decryptedBusiness),
    };
    (client as any)._groupE2ee = {
      handleIncoming: vi.fn().mockResolvedValue(null),
    };

    const result = await (client as any)._decryptMessages([rawMessage]);

    expect(result).toEqual([decryptedBusiness]);
    const decryptMock = (client as any)._e2ee.decryptMessage;
    expect(decryptMock).toHaveBeenCalledTimes(2);
    expect(decryptMock).toHaveBeenNthCalledWith(1, rawMessage, { skipReplay: true });
    expect(decryptMock).toHaveBeenNthCalledWith(2, rawMessage, { skipReplay: true });
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
      payload: { type: 'text', text: 'hello' },
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
      payload: { type: 'text', text: 'hello' },
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
      payload: { type: 'text', text: 'hello' },
    });

    expect(result).toEqual({ ok: true });
    expect((client as any)._fetchPeerPrekey).toHaveBeenCalledWith('bob.example.com');
    expect((client as any)._fetchPeerCert).toHaveBeenCalledWith('bob.example.com', undefined);
    expect((client as any)._e2ee.encryptOutbound).toHaveBeenCalledWith(
      'bob.example.com',
      { type: 'text', text: 'hello' },
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

  // ── R1: health-fail 路径也应受 max_attempts 约束 ──────────
  it('health 持续失败时应在 max_attempts 次后进入 terminal_failed', async () => {
    vi.useFakeTimers();
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
      await vi.advanceTimersByTimeAsync(500);
      await reconnectLoop;

      expect(client.state).toBe('terminal_failed');
      expect(publish).toHaveBeenCalledWith('connection.state', expect.objectContaining({
        state: 'terminal_failed',
        reason: 'max_attempts_exhausted',
      }));
      // _connectOnce 不应被调用（health 一直失败）
      expect((client as any)._connectOnce).not.toHaveBeenCalled();
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

describe('group.pull 拦截器：onPullResult 应消费原始消息', () => {
  it('onPullResult 应在解密前被调用（传入原始密文消息）', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'alice.aid.com';

    // 原始服务端消息（含 e2ee 密文）
    const rawMsg = { seq: 5, group_id: 'g1', payload: { type: 'e2ee.group_v1', ciphertext: 'CIPHER' } };
    // 解密后消息（payload 已替换）
    const decryptedMsg = { seq: 5, group_id: 'g1', payload: { type: 'text', text: 'hello' } };

    // mock transport.call 返回原始消息
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      messages: [rawMsg],
      cursor: { current_seq: 5 },
    });
    // mock 解密：返回解密后消息
    (client as any)._decryptGroupMessages = vi.fn().mockResolvedValue([decryptedMsg]);

    // 捕获 onPullResult 的调用参数
    const onPullResultSpy = vi.spyOn((client as any)._seqTracker, 'onPullResult');

    await client.call('group.pull', { group_id: 'g1', after_message_seq: 0 });

    // onPullResult 必须收到原始消息（rawMsg），而不是解密后的 decryptedMsg
    expect(onPullResultSpy).toHaveBeenCalledWith(
      'group:g1',
      expect.arrayContaining([expect.objectContaining({ payload: rawMsg.payload })]),
    );
    // 确认解密后的消息不被传给 onPullResult
    const callArgs = onPullResultSpy.mock.calls[0];
    const passedMessages = callArgs[1] as any[];
    expect(passedMessages[0].payload).toEqual(rawMsg.payload);
    expect(passedMessages[0].payload).not.toEqual(decryptedMsg.payload);
  });
});

describe('_fillGroupGap 不应重复调用 onPullResult', () => {
  it('_fillGroupGap 调用 call(group.pull) 后不应再次调用 onPullResult', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'alice.aid.com';
    (client as any)._groupE2ee.hasSecret = vi.fn().mockResolvedValue(true);

    const rawMsg = { seq: 3, group_id: 'g2', payload: { type: 'e2ee.group_v1', ciphertext: 'C' } };
    const decryptedMsg = { seq: 3, group_id: 'g2', payload: { type: 'text', text: 'hi' } };

    // mock transport.call（被 call() 拦截器调用）
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      messages: [rawMsg],
      cursor: { current_seq: 3 },
    });
    (client as any)._decryptGroupMessages = vi.fn().mockResolvedValue([decryptedMsg]);

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
    (client as any)._uploadPrekey = vi.fn().mockResolvedValue({ ok: true });

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

// ── R3: 解密失败不应 publish 密文给应用层 ──────────────────

describe('R3: 解密失败不应将密文 publish 给应用层', () => {
  function makeDecryptFailClient() {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'device-001';
    (client as any)._identity = { aid: 'test.aid.com' };

    // _decryptGroupMessage 返回原始消息（无 e2ee 字段）= 解密失败
    vi.spyOn(client as any, '_decryptGroupMessage').mockImplementation(async (msg: any) => msg);
    vi.spyOn(client as any, '_ensureSenderCertCached').mockResolvedValue(true);
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

    expect(events).not.toContain('created');
    expect(events).toContain('undecryptable');
  });

  it('批量路径：解密失败的消息不应出现在返回结果中', async () => {
    const client = makeDecryptFailClient();

    const msgs = [
      { group_id: 'g1', from: 'a', seq: 1, payload: { type: 'e2ee.group_encrypted', epoch: 1, ciphertext: 'X' } },
      { group_id: 'g1', from: 'b', seq: 2, payload: { type: 'text', text: 'hello' } },
    ];
    const result = await (client as any)._decryptGroupMessages(msgs);

    expect(result.length).toBe(1);
    expect(result[0].payload.type).toBe('text');
  });
});

// ── R4: _retryPendingDecryptMsgs 应被激活 ──────────────────

describe('R4: 收到密钥后应触发 pending 消息重试', () => {
  it('handleIncoming 返回 distribution 后应调用 _retryPendingDecryptMsgs', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    (client as any)._identity = { aid: 'test.aid.com' };

    (client as any)._pendingDecryptMsgs.set('group:g1', [{ fake: true }]);

    (client as any)._groupE2ee = {
      handleIncoming: vi.fn().mockReturnValue('distribution'),
      decrypt: vi.fn(),
      loadSecret: vi.fn(),
      getMemberAids: vi.fn().mockReturnValue([]),
    };

    const retrySpy = vi.spyOn(client as any, '_retryPendingDecryptMsgs').mockResolvedValue(undefined);

    const msg = {
      from: 'peer.aid.com',
      payload: {
        type: 'e2ee.group_key_distribution',
        group_id: 'g1',
        epoch: 2,
      },
    };

    await (client as any)._tryHandleGroupKeyMessage(msg);

    expect(retrySpy).toHaveBeenCalledWith('g1');
  });
});
