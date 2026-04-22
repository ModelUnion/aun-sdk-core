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

// ── ISSUE-JS-003 (P3): _syncAllGroupsOnce 不应静默吞异常 ──
describe('ISSUE-JS-003: _syncAllGroupsOnce 应记录日志', () => {
  it('_syncAllGroupsOnce catch 块应调用 console.warn', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    // 直接 mock call 方法使 group.list_my 抛错
    vi.spyOn(client, 'call').mockRejectedValue(new Error('rpc failed'));

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    await (client as any)._syncAllGroupsOnce();

    const warnMsg = warnSpy.mock.calls.find(
      c => typeof c[0] === 'string' && c[0].includes('上线群组同步失败')
    );
    warnSpy.mockRestore();
    expect(warnMsg).toBeDefined();
  });

  it('_syncAllGroupsOnce 失败应发布 group.sync_failed 事件', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    vi.spyOn(client, 'call').mockRejectedValue(new Error('rpc failed'));

    const publishSpy = vi.spyOn((client as any)._dispatcher, 'publish').mockResolvedValue(undefined);
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    await (client as any)._syncAllGroupsOnce();
    warnSpy.mockRestore();

    expect(publishSpy).toHaveBeenCalledWith('group.sync_failed', expect.objectContaining({
      error: expect.any(String),
    }));
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
    expect(client.state).toBe('disconnected');
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

  it('idle 状态调用 disconnect() 应安全无操作', async () => {
    const client = new AUNClient();
    await client.disconnect();
    // idle 状态不变
    expect(client.state).toBe('idle');
  });
});
