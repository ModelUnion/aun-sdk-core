// ── client-group-e2ee 模块单元测试（桩测试）──────────────────
// AUNClient 的群组 E2EE 编排逻辑需要完整的 Gateway 环境。
// 此处仅验证配置和状态相关的边界条件。
import 'fake-indexeddb/auto';
import { describe, it, expect, vi } from 'vitest';
import { AUNClient } from '../../src/client.js';

describe('AUNClient 群组 E2EE 配置', () => {
  it('默认启用群组 E2EE', () => {
    const client = new AUNClient();
    expect(client.configModel.groupE2ee).toBe(true);
  });

  it('构造期 groupE2ee 配置应被忽略并保持启用', () => {
    const client = new AUNClient({ groupE2ee: false } as any);
    expect(client.configModel.groupE2ee).toBe(true);
  });

  it('rotateOnJoin 默认为 false', () => {
    const client = new AUNClient();
    expect(client.configModel.rotateOnJoin).toBe(false);
  });

  it('epochAutoRotateInterval 默认为 0 秒', () => {
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

describe('群组成员变更事件的 epoch 轮换逻辑', () => {
  it('普通 member 收到 member_removed 事件时不应触发 rotate_epoch', async () => {
    vi.useFakeTimers();
    try {
      const client = new AUNClient();

      (client as any)._aid = 'member.aid.com';
      (client as any)._identity = { aid: 'member.aid.com' };
      (client as any)._state = 'connected';

      const rotateEpochSpy = vi.spyOn(client as any, '_rotateGroupEpoch').mockResolvedValue(undefined);
      const callSpy = vi.spyOn(client, 'call').mockImplementation(async (method, params) => {
        if (method === 'group.get_members') {
          expect(params).toEqual({ group_id: 'test-group-123' });
          return {
            members: [
              { aid: 'owner.aid.com', role: 'owner' },
              { aid: 'member.aid.com', role: 'member' },
            ],
          };
        }
        throw new Error(`unexpected method: ${method}`);
      });
      vi.spyOn(Math, 'random').mockReturnValue(0);

      await (client as any)._onRawGroupChanged({
        group_id: 'test-group-123',
        action: 'member_removed',
        member_aid: 'removed.aid.com',
      });
      await vi.runAllTimersAsync();

      expect(callSpy).toHaveBeenCalledWith('group.get_members', { group_id: 'test-group-123' });
      expect(rotateEpochSpy).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
      vi.restoreAllMocks();
    }
  });

  it('非 leader admin 在 epoch 已推进后不应兜底 rotate_epoch', async () => {
    vi.useFakeTimers();
    try {
      const client = new AUNClient();

      (client as any)._aid = 'zzz-admin.aid.com';
      (client as any)._identity = { aid: 'zzz-admin.aid.com' };
      (client as any)._state = 'connected';

      const rotateEpochSpy = vi.spyOn(client as any, '_rotateGroupEpoch').mockResolvedValue(undefined);
      const currentEpochSpy = vi.spyOn(client.groupE2ee, 'currentEpoch')
        .mockResolvedValueOnce(1)
        .mockResolvedValueOnce(2);
      const callSpy = vi.spyOn(client, 'call').mockImplementation(async (method, params) => {
        if (method === 'group.get_members') {
          expect(params).toEqual({ group_id: 'test-group-epoch' });
          return {
            members: [
              { aid: 'aaa-owner.aid.com', role: 'owner' },
              { aid: 'zzz-admin.aid.com', role: 'admin' },
            ],
          };
        }
        throw new Error(`unexpected method: ${method}`);
      });
      vi.spyOn(Math, 'random').mockReturnValue(0);

      await (client as any)._onRawGroupChanged({
        group_id: 'test-group-epoch',
        action: 'member_removed',
        member_aid: 'removed.aid.com',
      });
      await vi.runAllTimersAsync();

      expect(callSpy).toHaveBeenCalledWith('group.get_members', { group_id: 'test-group-epoch' });
      expect(currentEpochSpy).toHaveBeenCalledTimes(2);
      expect(rotateEpochSpy).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
      vi.restoreAllMocks();
    }
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
