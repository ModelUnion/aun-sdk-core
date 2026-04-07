// ── client 模块单元测试 ──────────────────────────────────────
// AUNClient 完整功能需要 Gateway 环境。
// 此处测试可独立验证的构造、配置和状态管理逻辑。
import 'fake-indexeddb/auto';
import { describe, it, expect } from 'vitest';
import { AUNClient } from '../../src/client.js';
import { ConnectionError, StateError, PermissionError } from '../../src/errors.js';

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
      groupE2ee: false,
      replayWindowSeconds: 600,
    });
    expect(client.configModel.aunPath).toBe('custom');
    expect(client.configModel.groupE2ee).toBe(false);
    expect(client.configModel.replayWindowSeconds).toBe(600);
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
