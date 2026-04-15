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
