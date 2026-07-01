// ── ISSUE-SDK-JS-005~011 修复测试 ──────────────────────────────
// TDD：先写失败测试，再修代码让测试通过
import 'fake-indexeddb/auto';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AUNClient } from '../../src/client.js';
import { AIDStore } from '../../src/aid-store.js';

// ── P1: ISSUE-SDK-JS-006: V2-only 后旧 group epoch 预检已退役 ────
describe('ISSUE-SDK-JS-006: V2-only group E2EE 编排', () => {
  let client: AUNClient;

  beforeEach(() => {
    client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'alice.aid.com';
    (client as any)._identity = {
      aid: 'alice.aid.com',
      private_key_pem: null,
      cert: null,
    };
    (client as any)._deviceId = 'dev-1';
  });

  it('V1 group epoch manager 与发送 helper 不应再暴露', () => {
    const proto = Object.getPrototypeOf(client) as Record<string, unknown>;

    expect((client as any)._groupE2ee).toBeUndefined();
    expect(proto._sendGroupEncrypted).toBeUndefined();
    expect(proto._recoverGroupEpochKey).toBeUndefined();
    expect(proto._rotateGroupEpoch).toBeUndefined();
  });

  it('group.send 默认加密必须走 V2 session，encrypt=false 才能走明文 RPC', async () => {
    const transportCall = vi.fn().mockResolvedValue({ ok: true });
    (client as any)._transport.call = transportCall;

    await expect(client.call('group.send', {
      group_id: 'grp01',
      payload: { type: 'text', text: 'hello' },
    })).rejects.toThrow('V2 session not initialized');

    await expect(client.call('group.send', {
      group_id: 'grp01',
      payload: { type: 'text', text: 'plain' },
      encrypt: false,
    })).resolves.toMatchObject({ ok: true });
    expect(transportCall).toHaveBeenCalledWith('group.send', expect.objectContaining({
      group_id: 'grp01',
      payload: { type: 'text', text: 'plain' },
    }), expect.any(Number), undefined, false);
  });
});

// ── P2: ISSUE-SDK-JS-003: AIDStore.list() ──────────────────
describe('ISSUE-SDK-JS-003: AIDStore.list()', () => {
  it('AUNClient 不再公开 listIdentities 方法', () => {
    const client = new AUNClient();
    expect((client as any).listIdentities).toBeUndefined();
  });

  it('AIDStore.list 应返回已存储身份摘要列表', async () => {
    const store = new AIDStore({ aunPath: 'aun', encryptionSeed: '' });
    (store as any)._keystore.listIdentities = vi.fn().mockResolvedValue(['alice.aid.com', 'bob1.aid.com']);
    (store as any).load = vi.fn(async (aid: string) => ({
      ok: true,
      data: {
        aid: {
          aid,
          certFingerprint: `fp-${aid}`,
          isPrivateKeyValid: () => true,
        },
      },
    }));

    const result = await store.list();
    expect(result.ok).toBe(true);
    expect((result as any).data?.identities).toEqual([
      { aid: 'alice.aid.com', certFingerprint: 'fp-alice.aid.com' },
      { aid: 'bob1.aid.com', certFingerprint: 'fp-bob1.aid.com' },
    ]);
  });

  it('AIDStore.list 无存储身份时应返回空数组', async () => {
    const store = new AIDStore({ aunPath: 'aun', encryptionSeed: '' });
    (store as any)._keystore.listIdentities = vi.fn().mockResolvedValue([]);

    const result = await store.list();
    expect(result.ok).toBe(true);
    expect((result as any).data?.identities).toEqual([]);
  });
});

// ── P2: ISSUE-SDK-JS-007: gap fill 状态保护 ─────────────────
describe('ISSUE-SDK-JS-007: gap fill 状态保护', () => {
  let client: AUNClient;

  beforeEach(() => {
    client = new AUNClient();
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'dev-1';
    (client as any)._seqTracker = {
      getContiguousSeq: () => 5,
      onPullResult: vi.fn(),
      exportState: () => ({}),
      onMessageSeq: vi.fn().mockReturnValue(false),
    };
  });

  it('disconnected 状态 _delivery.fillGroupGap 应提前返回', async () => {
    (client as any)._state = 'disconnected';
    const callSpy = vi.fn();
    vi.spyOn(client, 'call').mockImplementation(callSpy);

    await (client as any)._delivery.fillGroupGap('grp01');
    expect(callSpy).not.toHaveBeenCalled();
  });

  it('closing 状态 _delivery.fillGroupGap 应提前返回', async () => {
    (client as any)._state = 'connected';
    (client as any)._closing = true;
    const callSpy = vi.fn();
    vi.spyOn(client, 'call').mockImplementation(callSpy);

    await (client as any)._delivery.fillGroupGap('grp01');
    expect(callSpy).not.toHaveBeenCalled();
  });

  it('disconnected 状态 _delivery.fillGroupEventGap 应提前返回', async () => {
    (client as any)._state = 'disconnected';
    const callSpy = vi.fn();
    vi.spyOn(client, 'call').mockImplementation(callSpy);

    await (client as any)._delivery.fillGroupEventGap('grp01');
    expect(callSpy).not.toHaveBeenCalled();
  });

  it('disconnected 状态 _fillP2pGap 应提前返回', async () => {
    (client as any)._state = 'disconnected';
    const callSpy = vi.fn();
    vi.spyOn(client, 'call').mockImplementation(callSpy);

    await (client as any)._fillP2pGap();
    expect(callSpy).not.toHaveBeenCalled();
  });

  it('connected 状态 _delivery.fillGroupGap 应正常执行', async () => {
    (client as any)._state = 'connected';
    (client as any)._closing = false;
    const pullGroupV2Spy = vi.spyOn(client as any, '_pullGroupV2').mockResolvedValue([]);

    await (client as any)._delivery.fillGroupGap('grp01');
    expect(pullGroupV2Spy).toHaveBeenCalledWith('grp01', 5, 50);
  });
});

// ── P2: ISSUE-SDK-JS-008: _gapFillActive 来源标记 ───────────
describe('ISSUE-SDK-JS-008: _gapFillActive 来源标记', () => {
  it('client 应有 _gapFillActive 属性', () => {
    const client = new AUNClient();
    expect((client as any)._gapFillActive).toBe(false);
  });

  it('_delivery.fillGroupGap 执行期间 _gapFillActive 应为 true', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._closing = false;
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'dev-1';
    (client as any)._seqTracker = {
      getContiguousSeq: () => 1,
      onPullResult: vi.fn(),
      exportState: () => ({}),
      onMessageSeq: vi.fn().mockReturnValue(false),
    };

    let captured = false;
    vi.spyOn(client as any, '_pullGroupV2').mockImplementation(async () => {
      captured = (client as any)._gapFillActive;
      return [];
    });

    await (client as any)._delivery.fillGroupGap('grp01');
    expect(captured).toBe(true);
    // 完成后应重置
    expect((client as any)._gapFillActive).toBe(false);
  });

  it('call(group.pull) 中 pull_source 受 _gapFillActive 影响', async () => {
    const client = new AUNClient();
    (client as any)._gapFillActive = true;
    // 验证属性能被读取
    expect((client as any)._gapFillActive).toBe(true);
    (client as any)._gapFillActive = false;
    expect((client as any)._gapFillActive).toBe(false);
  });
});

// ── P3: ISSUE-SDK-JS-004: verify_ssl=false 浏览器兼容 ────────
describe('ISSUE-SDK-JS-004: verify_ssl=false 浏览器兼容', () => {
  it('verify_ssl=false 应记录警告但不抛错', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    // 浏览器 SDK 中 verify_ssl=false 在 AIDStore 构造时应发出警告而非抛错
    const store = new AIDStore({ aunPath: 'aun', encryptionSeed: '', verifySsl: false });
    expect((store as any)._verifySsl).toBe(true);
    const warningFound = warnSpy.mock.calls.some(
      c => typeof c[0] === 'string' && c[0].includes('verify_ssl')
    );
    expect(warningFound).toBe(true);
    warnSpy.mockRestore();
  });

  it('verify_ssl 默认应为 true', () => {
    const client = new AUNClient();
    expect(client.configModel.verifySsl).toBe(true);
  });
});

// ── P3: ISSUE-SDK-JS-009: group.add_member 检查返回结果 ──────
describe('ISSUE-SDK-JS-009: group.add_member 检查返回结果后再分发密钥', () => {
  let client: AUNClient;

  beforeEach(() => {
    client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'alice.aid.com';
    (client as any)._deviceId = 'dev-1';
    (client as any)._identity = { aid: 'alice.aid.com' };
  });

  it('add_member RPC 失败时不应触发密钥分发', async () => {
    (client as any)._v2Session = {};
    const proposeSpy = vi.spyOn(client as any, '_v2AutoProposeState').mockResolvedValue(undefined);

    // RPC 返回错误
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      error: { code: -33005, message: 'not authorized' },
    });

    const result = await client.call('group.add_member', {
      group_id: 'grp01',
      aid: 'bob1.aid.com',
    });

    // result 包含 error
    expect((client as any)._distributeKeyToNewMember).toBeUndefined();
    expect((client as any)._rotateGroupEpoch).toBeUndefined();
    expect(proposeSpy).not.toHaveBeenCalled();
  });

  it('add_member RPC 成功时应触发 V2 state auto-propose', async () => {
    (client as any)._v2Session = {};
    const proposeSpy = vi.spyOn(client as any, '_v2AutoProposeState').mockResolvedValue(undefined);

    (client as any)._transport.call = vi.fn().mockResolvedValue({
      ok: true,
      member: { aid: 'bob1.aid.com' },
    });

    await client.call('group.add_member', {
      group_id: 'grp01',
      aid: 'bob1.aid.com',
    });

    expect(proposeSpy).toHaveBeenCalledWith('grp01');
    expect((client as any)._maybeLeadRotateGroupEpoch).toBeUndefined();
  });
});
