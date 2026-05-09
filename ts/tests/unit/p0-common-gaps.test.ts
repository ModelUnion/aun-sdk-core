/**
 * P0 通用缺口测试 — 网关健康检查 / AID 参数校验 / 断线 RPC 拒绝
 *
 * 纯单元测试，无需真实服务端。
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { AUNClient } from '../../src/client.js';
import {
  ConnectionError,
  StateError,
  ValidationError,
  AuthError,
  PermissionError,
} from '../../src/errors.js';

// ── P0-01: 网关健康检查 ──────────────────────────────────────

describe('P0-01: 网关健康检查', () => {
  it('超时 — 不可达地址应在 timeout 内返回 false', async () => {
    const client = new AUNClient();
    // 192.0.2.0/24 是 RFC 5737 文档专用地址段，不可达
    const ok = await client.checkGatewayHealth('https://192.0.2.1:9999', 2000);
    expect(ok).toBe(false);
  }, 10_000);

  it('连接拒绝 — 无服务端口应返回 false', async () => {
    const client = new AUNClient();
    // 端口 1 几乎不会有服务监听，应被系统立即拒绝
    const ok = await client.checkGatewayHealth('https://127.0.0.1:1', 3000);
    expect(ok).toBe(false);
  }, 10_000);

  it('gatewayHealth 初始值应为 null', () => {
    const client = new AUNClient();
    expect(client.gatewayHealth).toBeNull();
  });

  it('健康检查后 gatewayHealth 应被更新', async () => {
    const client = new AUNClient();
    await client.checkGatewayHealth('https://127.0.0.1:1', 2000);
    // 检查完毕后 gatewayHealth 不再是 null，应为 false（无服务）
    expect(client.gatewayHealth).toBe(false);
  }, 10_000);
});

// ── P0-14: 断线中 RPC 拒绝 ──────────────────────────────────

describe('P0-14: 断线中 RPC 拒绝', () => {
  it('未连接时调用 call 抛出 ConnectionError', async () => {
    const client = new AUNClient();
    // 新创建的 client 处于 idle 状态，未连接
    await expect(client.call('meta.ping')).rejects.toThrow(ConnectionError);
  });

  it('未连接时调用 call 的错误消息应包含 not connected', async () => {
    const client = new AUNClient();
    await expect(client.call('meta.ping')).rejects.toThrow('not connected');
  });

  it('断线后调用 call 应抛出错误', async () => {
    const client = new AUNClient();
    // 模拟曾连接后断线的状态
    (client as any)._state = 'disconnected';
    await expect(
      client.call('message.send', { to: 'test.aid.com', content: { text: 'hi' } }),
    ).rejects.toThrow(ConnectionError);
  });

  it('internal_only 方法即使已连接也应被拒绝', async () => {
    const client = new AUNClient();
    // 模拟已连接状态
    (client as any)._state = 'connected';
    await expect(client.call('auth.login1')).rejects.toThrow(PermissionError);
    await expect(client.call('auth.login2')).rejects.toThrow(PermissionError);
    await expect(client.call('auth.connect')).rejects.toThrow(PermissionError);
  });

  it('internal_only 拒绝消息应包含 internal_only', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    await expect(client.call('auth.login1')).rejects.toThrow('internal_only');
  });
});

// ── P0-02: AID 创建参数校验 ─────────────────────────────────

describe('P0-02: AID 创建参数校验', () => {
  it('空 AID 应抛出错误', async () => {
    const client = new AUNClient();
    // AuthNamespace.createAid 对空 aid 直接抛 Error
    await expect(client.auth.createAid({ aid: '' })).rejects.toThrow();
  });

  it('空 AID 错误消息应包含 requires aid', async () => {
    const client = new AUNClient();
    await expect(client.auth.createAid({ aid: '' })).rejects.toThrow("requires 'aid'");
  });

  it('不传 aid 字段应抛出错误', async () => {
    const client = new AUNClient();
    await expect(client.auth.createAid({})).rejects.toThrow();
  });

  it('AID 名称过短（< 4 字符）应被 AuthFlow 拒绝', async () => {
    const client = new AUNClient();
    // 设置 _gatewayUrl 以跳过 discovery，触发 AuthFlow._validateAidName
    (client as any)._gatewayUrl = 'wss://localhost:9999';
    await expect(client.auth.createAid({ aid: 'ab' })).rejects.toThrow();
  });

  it('AID 名称含大写应被拒绝', async () => {
    const client = new AUNClient();
    (client as any)._gatewayUrl = 'wss://localhost:9999';
    await expect(client.auth.createAid({ aid: 'Alice.aid.com' })).rejects.toThrow();
  });

  it('AID 名称以 - 开头应被拒绝', async () => {
    const client = new AUNClient();
    (client as any)._gatewayUrl = 'wss://localhost:9999';
    await expect(client.auth.createAid({ aid: '-bad.aid.com' })).rejects.toThrow();
  });

  it('AID 名称以 guest 开头应被拒绝', async () => {
    const client = new AUNClient();
    (client as any)._gatewayUrl = 'wss://localhost:9999';
    await expect(client.auth.createAid({ aid: 'guestuser.aid.com' })).rejects.toThrow();
  });
});
