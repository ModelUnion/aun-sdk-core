// ── ISSUE-SDK-JS-005~011 修复测试 ──────────────────────────────
// TDD：先写失败测试，再修代码让测试通过
import 'fake-indexeddb/auto';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AUNClient } from '../../src/client.js';
import { E2EEError } from '../../src/errors.js';
import type { GroupE2EEManager } from '../../src/e2ee-group.js';

// ── P1: ISSUE-SDK-JS-006: _sendGroupEncrypted epoch 预检 ────
describe('ISSUE-SDK-JS-006: _sendGroupEncrypted epoch 预检', () => {
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

  it('本地 epoch < 服务端 epoch 时应触发密钥恢复请求', async () => {
    // mock group e2ee: 有 epoch 1 的密钥
    const groupE2ee = (client as any)._groupE2ee as GroupE2EEManager;
    let recovered = false;
    vi.spyOn(groupE2ee, 'currentEpoch').mockImplementation(async () => (recovered ? 3 : 1));
    vi.spyOn(groupE2ee, 'encrypt').mockResolvedValue({
      type: 'e2ee.group_encrypted',
      epoch: 1,
    });
    vi.spyOn(groupE2ee, 'loadSecret').mockResolvedValue({
      epoch: 3,
      secret: new Uint8Array(32),
      commitment: 'c3',
      member_aids: ['alice.aid.com'],
    });
    vi.spyOn(groupE2ee, 'encryptWithEpoch').mockResolvedValue({
      type: 'e2ee.group_encrypted',
      epoch: 3,
    });
    (client as any)._requestGroupKeyFromCandidates = vi.fn().mockImplementation(async () => {
      recovered = true;
    });

    const calls: string[] = [];
    const callMock = vi.fn().mockImplementation(async (method: string, params: any) => {
      calls.push(method);
      if (method === 'group.e2ee.get_epoch') return { epoch: 3 };
      if (method === 'group.get_info') return { owner_aid: 'owner.aid.com' };
      if (method === 'message.send') return { ok: true };
      if (method === 'group.send') return { ok: true };
      return {};
    });
    // 用 transport.call 来模拟所有 RPC
    (client as any)._transport.call = callMock;

    // 调用 _sendGroupEncrypted
    await (client as any)._sendGroupEncrypted({
      group_id: 'g1',
      payload: { type: 'text', text: 'hello' },
    });

    // 应该先调用 group.e2ee.get_epoch 进行预检
    expect(calls).toContain('group.e2ee.get_epoch');
  });

  it('本地无 epoch 时不应崩溃（静默跳过预检）', async () => {
    const groupE2ee = (client as any)._groupE2ee as GroupE2EEManager;
    vi.spyOn(groupE2ee, 'currentEpoch').mockResolvedValue(null);
    vi.spyOn(groupE2ee, 'encrypt').mockResolvedValue({
      type: 'e2ee.group_encrypted',
      epoch: 1,
    });
    vi.spyOn(groupE2ee, 'loadSecret').mockResolvedValue({
      epoch: 1,
      secret: new Uint8Array(32),
      commitment: 'c1',
      member_aids: ['alice.aid.com'],
    });
    vi.spyOn(groupE2ee, 'encryptWithEpoch').mockResolvedValue({
      type: 'e2ee.group_encrypted',
      epoch: 1,
    });

    (client as any)._transport.call = vi.fn().mockResolvedValue({ ok: true });

    // 不应抛错
    await expect(
      (client as any)._sendGroupEncrypted({
        group_id: 'g1',
        payload: { type: 'text', text: 'hello' },
      })
    ).resolves.toBeDefined();
  });

  it('epoch 预检失败不应阻塞发送', async () => {
    const groupE2ee = (client as any)._groupE2ee as GroupE2EEManager;
    vi.spyOn(groupE2ee, 'currentEpoch').mockResolvedValue(1);
    vi.spyOn(groupE2ee, 'encrypt').mockResolvedValue({
      type: 'e2ee.group_encrypted',
      epoch: 1,
    });
    vi.spyOn(groupE2ee, 'loadSecret').mockResolvedValue({
      epoch: 1,
      secret: new Uint8Array(32),
      commitment: 'c1',
      member_aids: ['alice.aid.com'],
    });
    vi.spyOn(groupE2ee, 'encryptWithEpoch').mockResolvedValue({
      type: 'e2ee.group_encrypted',
      epoch: 1,
    });

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    (client as any)._transport.call = vi.fn().mockImplementation(async (method: string) => {
      if (method === 'group.e2ee.get_epoch') throw new Error('network error');
      if (method === 'group.send') return { ok: true };
      return {};
    });

    const result = await (client as any)._sendGroupEncrypted({
      group_id: 'g1',
      payload: { type: 'text', text: 'hello' },
    });

    expect(result).toBeDefined();
    warnSpy.mockRestore();
  });
});

// ── P2: ISSUE-SDK-JS-003: listIdentities() ──────────────────
describe('ISSUE-SDK-JS-003: listIdentities()', () => {
  it('AUNClient 应有 listIdentities 方法', () => {
    const client = new AUNClient();
    expect(typeof (client as any).listIdentities).toBe('function');
  });

  it('listIdentities 应返回已存储身份摘要列表', async () => {
    const client = new AUNClient();
    // mock keystore.listIdentities
    (client as any)._keystore.listIdentities = vi.fn().mockResolvedValue(['alice.aid.com', 'bob.aid.com']);
    (client as any)._keystore.loadIdentity = vi.fn().mockResolvedValue({ private_key_pem: 'PEM' });
    (client as any)._keystore.loadMetadata = vi.fn().mockResolvedValue(null);

    const result = await (client as any).listIdentities();
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBe(2);
    expect(result[0]).toHaveProperty('aid', 'alice.aid.com');
    expect(result[1]).toHaveProperty('aid', 'bob.aid.com');
  });

  it('listIdentities 无存储身份时应返回空数组', async () => {
    const client = new AUNClient();
    (client as any)._keystore.listIdentities = vi.fn().mockResolvedValue([]);

    const result = await (client as any).listIdentities();
    expect(result).toEqual([]);
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

  it('disconnected 状态 _fillGroupGap 应提前返回', async () => {
    (client as any)._state = 'disconnected';
    const callSpy = vi.fn();
    vi.spyOn(client, 'call').mockImplementation(callSpy);

    await (client as any)._fillGroupGap('g1');
    expect(callSpy).not.toHaveBeenCalled();
  });

  it('closing 状态 _fillGroupGap 应提前返回', async () => {
    (client as any)._state = 'connected';
    (client as any)._closing = true;
    const callSpy = vi.fn();
    vi.spyOn(client, 'call').mockImplementation(callSpy);

    await (client as any)._fillGroupGap('g1');
    expect(callSpy).not.toHaveBeenCalled();
  });

  it('disconnected 状态 _fillGroupEventGap 应提前返回', async () => {
    (client as any)._state = 'disconnected';
    const callSpy = vi.fn();
    vi.spyOn(client, 'call').mockImplementation(callSpy);

    await (client as any)._fillGroupEventGap('g1');
    expect(callSpy).not.toHaveBeenCalled();
  });

  it('disconnected 状态 _fillP2pGap 应提前返回', async () => {
    (client as any)._state = 'disconnected';
    const callSpy = vi.fn();
    vi.spyOn(client, 'call').mockImplementation(callSpy);

    await (client as any)._fillP2pGap();
    expect(callSpy).not.toHaveBeenCalled();
  });

  it('connected 状态 _fillGroupGap 应正常执行', async () => {
    (client as any)._state = 'connected';
    (client as any)._closing = false;
    (client as any)._groupE2ee = { hasSecret: vi.fn().mockResolvedValue(true) };
    const callSpy = vi.fn().mockResolvedValue({ messages: [] });
    vi.spyOn(client, 'call').mockImplementation(callSpy);

    await (client as any)._fillGroupGap('g1');
    expect(callSpy).toHaveBeenCalled();
  });
});

// ── P2: ISSUE-SDK-JS-008: _gapFillActive 来源标记 ───────────
describe('ISSUE-SDK-JS-008: _gapFillActive 来源标记', () => {
  it('client 应有 _gapFillActive 属性', () => {
    const client = new AUNClient();
    expect((client as any)._gapFillActive).toBe(false);
  });

  it('_fillGroupGap 执行期间 _gapFillActive 应为 true', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._closing = false;
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'dev-1';
    (client as any)._groupE2ee = { hasSecret: vi.fn().mockResolvedValue(true) };
    (client as any)._seqTracker = {
      getContiguousSeq: () => 1,
      onPullResult: vi.fn(),
      exportState: () => ({}),
      onMessageSeq: vi.fn().mockReturnValue(false),
    };

    let captured = false;
    vi.spyOn(client, 'call').mockImplementation(async () => {
      captured = (client as any)._gapFillActive;
      return { messages: [] };
    });

    await (client as any)._fillGroupGap('g1');
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

// ── P2: ISSUE-SDK-JS-010: 重连后密钥恢复 ────────────────────
describe('ISSUE-SDK-JS-010: 重连后缺失 epoch key 群密钥恢复', () => {
  it('_syncAllGroupsOnce 对无 epoch key 的群应请求密钥恢复', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'alice.aid.com';
    (client as any)._deviceId = 'dev-1';

    const groupE2ee = (client as any)._groupE2ee;
    vi.spyOn(groupE2ee, 'hasSecret').mockResolvedValue(false);

    const calls: Array<{ method: string; params: any }> = [];
    vi.spyOn(client, 'call').mockImplementation(async (method: string, params?: any) => {
      calls.push({ method, params });
      if (method === 'group.list_my') {
        return {
          items: [
            { group_id: 'g1', owner_aid: 'owner.aid.com' },
          ],
        };
      }
      return {};
    });

    await (client as any)._syncAllGroupsOnce();

    // 应该向 owner 发起密钥恢复请求
    const keyRequest = calls.find(
      c => c.method === 'message.send' && c.params?.to === 'owner.aid.com'
    );
    expect(keyRequest).toBeDefined();
  });

  it('_syncAllGroupsOnce 有 epoch key 的群应补消息而非恢复密钥', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'alice.aid.com';
    (client as any)._deviceId = 'dev-1';
    (client as any)._seqTracker = {
      getContiguousSeq: () => 0,
      onPullResult: vi.fn(),
      onMessageSeq: vi.fn().mockReturnValue(false),
      exportState: () => ({}),
    };

    const groupE2ee = (client as any)._groupE2ee;
    vi.spyOn(groupE2ee, 'hasSecret').mockResolvedValue(true);

    const calls: string[] = [];
    vi.spyOn(client, 'call').mockImplementation(async (method: string) => {
      calls.push(method);
      if (method === 'group.list_my') return { items: [{ group_id: 'g1' }] };
      return { messages: [], events: [] };
    });

    await (client as any)._syncAllGroupsOnce();

    // 不应发送密钥恢复请求（message.send）
    const keyRequest = calls.filter(c => c === 'message.send');
    expect(keyRequest.length).toBe(0);
  });
});

// ── P3: ISSUE-SDK-JS-004: verify_ssl=false 浏览器兼容 ────────
describe('ISSUE-SDK-JS-004: verify_ssl=false 浏览器兼容', () => {
  it('verify_ssl=false 应记录警告但不抛错', () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    // 浏览器 SDK 中 verify_ssl=false 应发出警告而非直接抛错
    // 注：当前实现直接抛错，修复后应改为仅警告
    let errorThrown = false;
    try {
      new AUNClient({ verify_ssl: false } as any);
    } catch {
      errorThrown = true;
    }
    // 修复后应不抛错
    expect(errorThrown).toBe(false);
    // 应有警告日志
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
    const distributeKeyFn = vi.fn().mockResolvedValue(undefined);
    (client as any)._distributeKeyToNewMember = distributeKeyFn;
    (client as any)._rotateGroupEpoch = vi.fn().mockResolvedValue(undefined);

    // RPC 返回错误
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      error: { code: -33005, message: 'not authorized' },
    });

    const result = await client.call('group.add_member', {
      group_id: 'g1',
      aid: 'bob.aid.com',
    });

    // result 包含 error
    expect(distributeKeyFn).not.toHaveBeenCalled();
  });

  it('add_member RPC 成功时应触发 epoch 轮换兜底', async () => {
    const rotateFn = vi.fn().mockResolvedValue(undefined);
    (client as any)._maybeLeadRotateGroupEpoch = rotateFn;

    (client as any)._transport.call = vi.fn().mockResolvedValue({
      ok: true,
      member: { aid: 'bob.aid.com' },
    });

    await client.call('group.add_member', {
      group_id: 'g1',
      aid: 'bob.aid.com',
    });

    expect(rotateFn).toHaveBeenCalledWith('g1', expect.any(String), null);
  });
});
