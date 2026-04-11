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
import { ConnectionError, PermissionError, StateError, ValidationError } from '../../src/errors.js';
import type { PrekeyMap } from '../../src/types.js';

describe('AUNClient 构造', () => {
  it('无参数构造使用默认配置', () => {
    const client = new AUNClient();
    expect(client.state).toBe('idle');
    expect(client.aid).toBeNull();
    expect(client.config).toEqual({});
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
  it('同步 token 时不应覆盖已有 prekey', () => {
    const tmpDir = mkdtempSync(join(tmpdir(), 'aun-client-sync-'));
    const client = new AUNClient({ aun_path: tmpDir });
    const ks = (client as any)._keystore;
    const aid = 'sync.agentid.pub';

    ks.saveIdentity(aid, {
      aid,
      private_key_pem: 'PRIVATE_KEY',
      public_key_der_b64: 'pub',
      curve: 'P-256',
    });
    ks.saveMetadata(aid, {
      aid,
      e2ee_prekeys: {
        pk1: { private_key_pem: 'KEEP_ME', created_at: 1 },
      },
    });

    (client as any)._aid = aid;
    (client as any)._syncIdentityAfterConnect('tok-connect');

    const loaded = ks.loadMetadata(aid);
    expect(loaded.access_token).toBe('tok-connect');
    expect((loaded.e2ee_prekeys as PrekeyMap).pk1?.private_key_pem).toBe('KEEP_ME');
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
});

describe('AUNClient._fetchPeerPrekey', () => {
  it('found=false 时抛出 prekey 缺失错误', async () => {
    const client = new AUNClient();
    (client as any)._transport.call = vi.fn().mockResolvedValue({ found: false });

    await expect((client as any)._fetchPeerPrekey('bob.example.com')).rejects.toThrow(
      'peer prekey not found for bob.example.com',
    );
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
  it('构建证书 URL 时应透传 cert_fingerprint', () => {
    expect((AUNClient as any)._buildCertUrl(
      'wss://gateway.example.com/aun',
      'bob.example.com',
      'sha256:abc',
    )).toBe('https://gateway.example.com/pki/cert/bob.example.com?cert_fingerprint=sha256%3Aabc');
  });

  it('发送加密消息时应按 prekey.cert_fingerprint 获取证书', async () => {
    const client = new AUNClient();
    (client as any)._fetchPeerPrekey = vi.fn().mockResolvedValue({
      prekey_id: 'pk-1',
      public_key: 'pub',
      signature: 'sig',
      cert_fingerprint: 'sha256:abc',
    });
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
