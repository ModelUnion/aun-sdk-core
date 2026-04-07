// ── client-group-e2ee 模块单元测试（桩测试）──────────────────
// AUNClient 的群组 E2EE 编排逻辑需要完整的 Gateway 环境。
// 此处仅验证配置和状态相关的边界条件。
import 'fake-indexeddb/auto';
import { describe, it, expect } from 'vitest';
import { AUNClient } from '../../src/client.js';

describe('AUNClient 群组 E2EE 配置', () => {
  it('默认启用群组 E2EE', () => {
    const client = new AUNClient();
    expect(client.configModel.groupE2ee).toBe(true);
  });

  it('可通过配置禁用群组 E2EE', () => {
    const client = new AUNClient({ groupE2ee: false });
    expect(client.configModel.groupE2ee).toBe(false);
  });

  it('rotateOnJoin 默认为 false', () => {
    const client = new AUNClient();
    expect(client.configModel.rotateOnJoin).toBe(false);
  });

  it('epochAutoRotateInterval 默认为 0（禁用）', () => {
    const client = new AUNClient();
    expect(client.configModel.epochAutoRotateInterval).toBe(0);
  });

  it('oldEpochRetentionSeconds 默认为 7 天', () => {
    const client = new AUNClient();
    expect(client.configModel.oldEpochRetentionSeconds).toBe(604800);
  });
});

describe('AUNClient 群组 E2EE 管理器', () => {
  it('groupE2ee 应为 GroupE2EEManager 实例', () => {
    const client = new AUNClient();
    const ge = client.groupE2ee;
    expect(ge).toBeDefined();
    // 验证关键方法存在
    expect(typeof ge.createEpoch).toBe('function');
    expect(typeof ge.rotateEpoch).toBe('function');
    expect(typeof ge.encrypt).toBe('function');
    expect(typeof ge.decrypt).toBe('function');
    expect(typeof ge.hasSecret).toBe('function');
    expect(typeof ge.currentEpoch).toBe('function');
    expect(typeof ge.getMemberAids).toBe('function');
    expect(typeof ge.handleIncoming).toBe('function');
  });
});

// 注意: 以下测试需要完整 Gateway 环境，标记为 TODO
// - group.create 后自动创建 epoch
// - group.add_member 后自动分发密钥
// - group.kick 后自动轮换 epoch
// - group.send 自动加密
// - group.pull 自动解密
// - 群组变更事件触发 epoch 轮换
// - 密钥恢复流程
