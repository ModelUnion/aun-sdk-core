// ── ISSUE-JS-001~004 修复测试 ──────────────────────────────
import 'fake-indexeddb/auto';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AUNClient } from '../../src/client.js';

// ── ISSUE-JS-001 (P2): close() 应发送 auth.logout RPC ──────
describe('ISSUE-JS-001: close() 应发送 auth.logout', () => {
  let client: AUNClient;

  beforeEach(() => {
    client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    (client as any)._transport.call = vi.fn().mockResolvedValue({});
    (client as any)._transport.close = vi.fn().mockResolvedValue(undefined);
  });

  it('close() 应在关闭 WebSocket 前发送 auth.logout RPC', async () => {
    const callOrder: string[] = [];
    (client as any)._transport.call = vi.fn().mockImplementation(async (method: string) => {
      callOrder.push(`call:${method}`);
      return {};
    });
    (client as any)._transport.close = vi.fn().mockImplementation(async () => {
      callOrder.push('close');
    });

    await client.close();

    expect(callOrder).toContain('call:auth.logout');
    expect(callOrder.indexOf('call:auth.logout')).toBeLessThan(callOrder.indexOf('close'));
  });

  it('auth.logout 失败不应阻止 close() 完成', async () => {
    (client as any)._transport.call = vi.fn().mockRejectedValue(new Error('network error'));
    (client as any)._transport.close = vi.fn().mockResolvedValue(undefined);

    await client.close();
    expect(client.state).toBe('closed');
  });

  it('idle 状态 close() 不应发送 auth.logout', async () => {
    (client as any)._state = 'idle';
    const callSpy = vi.fn();
    (client as any)._transport.call = callSpy;

    await client.close();
    expect(callSpy).not.toHaveBeenCalled();
  });
});

// ── ISSUE-JS-002 (P2): 签名失败应抛错而非降级 ──────────────
describe('ISSUE-JS-002: 签名失败应抛错而非静默降级', () => {
  let client: AUNClient;

  beforeEach(() => {
    client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    // 设置一个无效的私钥，使签名必然失败
    (client as any)._identity = {
      aid: 'test.aid.com',
      private_key_pem: 'INVALID_PEM_KEY',
      cert: '',
    };
    (client as any)._currentAid = {
      aid: 'test.aid.com',
      privateKeyPem: 'INVALID_PEM_KEY',
      certPem: '',
    };
    (client as any)._transport.call = vi.fn().mockResolvedValue({ ok: true });
  });

  it('签名失败时 _signClientOperation 应抛出错误', async () => {
    await expect(
      (client as any)._signClientOperation('group.send', { group_id: 'g1' })
    ).rejects.toThrow();
  });

  it('签名失败时 call() 对 SIGNED_METHODS 应抛错', async () => {
    await expect(
      client.call('group.leave', { group_id: 'g1' })
    ).rejects.toThrow();
  });
});

// ── ISSUE-JS-004 (P3): 缺少 disconnect() 别名方法 ──────────
describe('ISSUE-JS-004: disconnect() 别名方法', () => {
  it('disconnect() 方法应存在', () => {
    const client = new AUNClient();
    expect(typeof client.disconnect).toBe('function');
  });

  it('disconnect() 应断开连接但保留可重连状态', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._transport.call = vi.fn().mockResolvedValue({});
    (client as any)._transport.close = vi.fn().mockResolvedValue(undefined);

    await client.disconnect();
    expect(client.state).toBe('standby');
  });

  it('disconnect() 后应可重新 connect()', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._transport.call = vi.fn().mockResolvedValue({});
    (client as any)._transport.close = vi.fn().mockResolvedValue(undefined);

    await client.disconnect();
    // 状态应为 disconnected 而非 closed
    expect(client.state).not.toBe('closed');
  });

  it('retry_backoff 状态调用 disconnect() 应停止重连循环', async () => {
    const client = new AUNClient();
    const abort = vi.fn();
    (client as any)._state = 'retry_backoff';
    (client as any)._reconnectAbort = { abort };
    (client as any)._reconnectActive = true;
    (client as any)._transport.close = vi.fn().mockResolvedValue(undefined);

    await client.disconnect();

    expect(abort).toHaveBeenCalledTimes(1);
    expect((client as any)._reconnectAbort).toBeNull();
    expect((client as any)._reconnectActive).toBe(false);
    expect(client.state).toBe('standby');
  });

  it('idle 状态调用 disconnect() 应安全无操作', async () => {
    const client = new AUNClient();
    await client.disconnect();
    // idle 状态不变
    expect(client.state).toBe('no_identity');
  });
});
