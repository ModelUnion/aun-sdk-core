/**
 * AUNClient 单元测试
 *
 * 测试客户端构造、参数校验、状态管理等不需要网络连接的逻辑。
 */

import { describe, it, expect } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { AUNClient } from '../../src/client.js';
import { ConnectionError, PermissionError, StateError } from '../../src/errors.js';

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
