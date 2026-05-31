// ── client-group-e2ee 模块单元测试（桩测试）──────────────────
// 此处验证浏览器 SDK 已切到 E2EE V2-only 的群组编排入口。
import 'fake-indexeddb/auto';
import { describe, it, expect, vi } from 'vitest';
import { AUNClient } from '../../src/client.js';

describe('AUNClient 群组 E2EE 配置', () => {
  it('默认启用群组 E2EE', () => {
    const client = new AUNClient();
    expect(client.configModel.groupE2ee).toBe(true);
  });

  it('构造期旧配置对象应被拒绝，不能通过 groupE2ee 关闭 V2-only 群加密', () => {
    expect(() => new AUNClient({ groupE2ee: false } as any)).toThrow(/AID object/);
  });

  it('构造期 V1 epoch 配置应被拒绝', () => {
    expect(() => new AUNClient({
      epochAutoRotateInterval: 30,
      oldEpochRetentionSeconds: 60,
    } as any)).toThrow(/AID object/);
    const client = new AUNClient();
    expect((client.configModel as any).epochAutoRotateInterval).toBeUndefined();
    expect((client.configModel as any).oldEpochRetentionSeconds).toBeUndefined();
  });
});

describe('AUNClient 群组 E2EE V2-only 语义', () => {
  it('不再暴露 V1 GroupE2EEManager 与 epoch helper', () => {
    const client = new AUNClient();
    expect((client as any).groupE2ee).toBeUndefined();
    expect((client as any)._groupE2ee).toBeUndefined();
    for (const name of [
      '_isGroupEpochTooOldError',
      '_isGroupEpochChangedDuringSendError',
      '_isRecoverableGroupEpochError',
      '_rotateGroupEpoch',
      '_maybeLeadRotateGroupEpoch',
      '_distributeKeyToNewMember',
    ]) {
      expect((client as any)[name], `${name} should be removed in V2-only client`).toBeUndefined();
    }
  });
});

describe('群组成员变更事件的 V2-only 编排', () => {
  it('member_removed 不再触发 V1 epoch 轮换或 group.e2ee.* RPC', async () => {
    const client = new AUNClient();
    (client as any)._aid = 'member.aid.com';
    (client as any)._identity = { aid: 'member.aid.com' };
    (client as any)._state = 'connected';

    const callSpy = vi.spyOn(client, 'call').mockResolvedValue({});

    await (client as any)._onRawGroupChanged({
      group_id: 'test-group-123',
      action: 'member_removed',
      member_aid: 'removed.aid.com',
      old_epoch: 5,
    });

    expect((client as any)._rotateGroupEpoch).toBeUndefined();
    expect(callSpy).not.toHaveBeenCalled();
  });

  it('upsert 且 V2 session 就绪时触发 V2 state auto-propose', async () => {
    const client = new AUNClient();
    (client as any)._aid = 'owner.aid.com';
    (client as any)._identity = { aid: 'owner.aid.com' };
    (client as any)._state = 'connected';
    (client as any)._v2Session = {};
    const proposeSpy = vi.spyOn(client as any, '_v2AutoProposeState').mockResolvedValue(undefined);

    await (client as any)._onRawGroupChanged({
      group_id: 'test-group-v2',
      action: 'upsert',
      event_seq: 1,
    });

    expect(proposeSpy).toHaveBeenCalledWith('test-group-v2', { leaderDelay: true });
  });

  it('invite_code_used 应触发 propose，并让已有成员轮换 group SPK', async () => {
    const client = new AUNClient();
    (client as any)._aid = 'alice.aid.com';
    (client as any)._identity = { aid: 'alice.aid.com' };
    (client as any)._state = 'connected';
    const ensureGroupRegistered = vi.fn().mockResolvedValue(undefined);
    const rotateGroupSPK = vi.fn().mockResolvedValue(undefined);
    (client as any)._v2Session = { ensureGroupRegistered, rotateGroupSPK };
    const proposeSpy = vi.spyOn(client as any, '_v2AutoProposeState').mockResolvedValue(undefined);

    await (client as any)._onRawGroupChanged({
      group_id: 'test-group-v2',
      action: 'invite_code_used',
      member_aid: 'bob.aid.com',
      actor_aid: 'bob.aid.com',
    });

    expect(proposeSpy).toHaveBeenCalledWith('test-group-v2', { leaderDelay: true });
    expect(rotateGroupSPK).toHaveBeenCalled();
    expect(ensureGroupRegistered).not.toHaveBeenCalled();
  });
});
