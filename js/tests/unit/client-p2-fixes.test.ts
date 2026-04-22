// ── P2 问题修复测试 ──────────────────────────────────────
// 测试 P2-5/6/7/8 四个问题的修复
import 'fake-indexeddb/auto';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AUNClient } from '../../src/client.js';

describe('P2-5: group.pull 应喂原始消息给 onPullResult', () => {
  let client: AUNClient;

  beforeEach(() => {
    client = new AUNClient();
    (client as any)._transport.call = vi.fn();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'device-001';
  });

  it('group.pull 应使用原始消息（解密前）喂 SeqTracker', async () => {
    const rawMessages = [
      { seq: 1, content: 'encrypted-payload-1' },
      { seq: 2, content: 'encrypted-payload-2' },
    ];

    (client as any)._transport.call.mockResolvedValue({
      messages: rawMessages,
      cursor: { current_seq: 2 },
    });

    const onPullResultSpy = vi.spyOn((client as any)._seqTracker, 'onPullResult');

    await client.call('group.pull', {
      group_id: 'group-123',
      after_message_seq: 0,
      device_id: 'device-001',
    });

    // 验证 onPullResult 收到的是原始消息（含原始 content），不是解密后的
    expect(onPullResultSpy).toHaveBeenCalledWith(
      'group:group-123',
      expect.arrayContaining([
        expect.objectContaining({ seq: 1, content: 'encrypted-payload-1' }),
        expect.objectContaining({ seq: 2, content: 'encrypted-payload-2' }),
      ])
    );
  });
});

describe('P2-6: 补洞路径不应重复调用 onPullResult', () => {
  let client: AUNClient;

  beforeEach(() => {
    client = new AUNClient();
    (client as any)._transport.call = vi.fn();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'device-001';
  });

  it('_fillP2pGap 不应重复调用 onPullResult', async () => {
    const messages = [
      { seq: 3, content: 'msg-3' },
      { seq: 4, content: 'msg-4' },
    ];

    (client as any)._transport.call.mockResolvedValue({ messages });

    const onPullResultSpy = vi.spyOn((client as any)._seqTracker, 'onPullResult');

    // 模拟已有 seq 1-2 的状态，设置 contiguous_seq > 0 以通过 afterSeq === 0 守卫
    (client as any)._seqTracker.onPullResult('p2p:test.aid.com', [{ seq: 1 }, { seq: 2 }]);
    onPullResultSpy.mockClear();

    await (client as any)._fillP2pGap();

    // call('message.pull') 拦截器内部会调用一次 onPullResult
    // _fillP2pGap 内不应再重复调用
    expect(onPullResultSpy).toHaveBeenCalledTimes(1);
  });

  it('_fillGroupGap 不应重复调用 onPullResult', async () => {
    const messages = [
      { seq: 3, content: 'msg-3' },
      { seq: 4, content: 'msg-4' },
    ];

    (client as any)._transport.call.mockResolvedValue({
      messages,
      cursor: { current_seq: 4 },
    });

    const onPullResultSpy = vi.spyOn((client as any)._seqTracker, 'onPullResult');

    // 模拟已有 seq 1-2 的状态
    (client as any)._seqTracker.onPullResult('group:group-123', [{ seq: 1 }, { seq: 2 }]);
    onPullResultSpy.mockClear();

    await (client as any)._fillGroupGap('group-123');

    // call('group.pull') 拦截器内部会调用一次 onPullResult
    // _fillGroupGap 内不应再重复调用
    expect(onPullResultSpy).toHaveBeenCalledTimes(1);
  });
});

describe('P2-7: 断线后应停止后台任务', () => {
  let client: AUNClient;

  beforeEach(() => {
    client = new AUNClient();
    (client as any)._transport.call = vi.fn().mockResolvedValue({});
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
  });

  it('_handleTransportDisconnect 应调用 _stopBackgroundTasks', async () => {
    const stopSpy = vi.spyOn(client as any, '_stopBackgroundTasks');
    // 关闭自动重连以避免 reconnectLoop 改变状态
    (client as any)._sessionOptions = {
      ...(client as any)._sessionOptions,
      auto_reconnect: false,
    };

    // 模拟断线
    await (client as any)._handleTransportDisconnect(new Error('connection lost'));

    expect(stopSpy).toHaveBeenCalled();
    expect((client as any)._state).toBe('disconnected');
  });

  it('断线后心跳定时器应被清理', async () => {
    // 手动设置一个假定时器
    (client as any)._heartbeatTimer = setInterval(() => {}, 100000);
    expect((client as any)._heartbeatTimer).not.toBeNull();

    // 关闭自动重连
    (client as any)._sessionOptions = {
      ...(client as any)._sessionOptions,
      auto_reconnect: false,
    };

    // 模拟断线
    await (client as any)._handleTransportDisconnect(new Error('connection lost'));

    expect((client as any)._heartbeatTimer).toBeNull();
  });

  it('断线后 token 刷新定时器应被清理', async () => {
    (client as any)._tokenRefreshTimer = setTimeout(() => {}, 100000);
    expect((client as any)._tokenRefreshTimer).not.toBeNull();

    (client as any)._sessionOptions = {
      ...(client as any)._sessionOptions,
      auto_reconnect: false,
    };

    await (client as any)._handleTransportDisconnect(new Error('connection lost'));

    expect((client as any)._tokenRefreshTimer).toBeNull();
  });
});

describe('P2-8: _restoreSeqTrackerState 应真正 await', () => {
  it('_restoreSeqTrackerState 返回 Promise 且应该正确恢复状态', async () => {
    const client = new AUNClient();
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'device-001';
    (client as any)._slotId = 'slot-001';
    (client as any)._seqTrackerContext = JSON.stringify(['test.aid.com', 'device-001', 'slot-001']);

    // 模拟慢速 IndexedDB
    let resolveLoad: (v: any) => void;
    const loadPromise = new Promise((resolve) => { resolveLoad = resolve; });

    (client as any)._keystore = {
      loadAllSeqs: vi.fn().mockImplementation(() => loadPromise),
    };

    // 启动 restore 并验证它返回一个 promise
    const restorePromise = (client as any)._restoreSeqTrackerState();
    expect(restorePromise).toBeInstanceOf(Promise);

    // 此时 tracker 应该还没恢复
    expect((client as any)._seqTracker.getContiguousSeq('p2p:test.aid.com')).toBe(0);

    // 完成加载
    resolveLoad!({ 'p2p:test.aid.com': 10 });
    await restorePromise;

    // await 后 tracker 应该恢复状态
    expect((client as any)._seqTracker.getContiguousSeq('p2p:test.aid.com')).toBe(10);
  });

  it('_connectOnce 中 restore 应在 transport.connect 之前完成', async () => {
    const client = new AUNClient();
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'device-001';

    // 跟踪调用顺序
    const callOrder: string[] = [];

    (client as any)._restoreSeqTrackerState = vi.fn().mockImplementation(async () => {
      // 模拟 100ms 慢速 IndexedDB
      await new Promise(resolve => setTimeout(resolve, 50));
      callOrder.push('restore');
    });

    (client as any)._transport.connect = vi.fn().mockImplementation(async () => {
      callOrder.push('connect');
      return 'challenge-123';
    });

    (client as any)._auth = {
      setInstanceContext: vi.fn(),
      connectSession: vi.fn().mockResolvedValue({
        identity: { aid: 'test.aid.com' },
        token: 'token-123',
      }),
      getAccessTokenExpiry: vi.fn().mockReturnValue(null),
      cleanExpiredCaches: vi.fn(),
    };
    (client as any)._startBackgroundTasks = vi.fn();
    (client as any)._uploadPrekey = vi.fn().mockResolvedValue({ ok: true });

    await (client as any)._connectOnce({
      access_token: 'token-123',
      gateway: 'wss://localhost/aun',
    }, true);

    // restore 必须在 transport.connect 之前完成
    expect(callOrder.indexOf('restore')).toBeLessThan(callOrder.indexOf('connect'));
  });
});

// ── close_code 1000 误判测试 ──────────────────────────────

describe('close_code 1000 不应视为 serverInitiated', () => {
  let client: AUNClient;

  beforeEach(() => {
    client = new AUNClient();
    (client as any)._transport.call = vi.fn().mockResolvedValue({});
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    (client as any)._sessionOptions = {
      ...(client as any)._sessionOptions,
      auto_reconnect: false,
    };
  });

  it('close_code=1000 时 serverInitiated 应为 false', async () => {
    // 测试 _handleTransportDisconnect 中对 closeCode 的处理
    // 1000 是正常关闭，不应被视为服务端主动关闭
    const startReconnectSpy = vi.spyOn(client as any, '_reconnectLoop').mockResolvedValue(undefined);

    // 开启自动重连以测试 serverInitiated 参数
    (client as any)._sessionOptions.auto_reconnect = true;

    await (client as any)._handleTransportDisconnect(new Error('closed'), 1000);

    // closeCode=1000 不应触发重连（它是正常关闭）
    // 或者如果触发了，serverInitiated 应为 false
    if (startReconnectSpy.mock.calls.length > 0) {
      const serverInitiated = startReconnectSpy.mock.calls[0][0];
      expect(serverInitiated).toBe(false);
    }
  });
});

// ── group.add_member 密钥分发结果检查测试 ──────────────────

describe('group.add_member 失败时不应分发密钥', () => {
  let client: AUNClient;

  beforeEach(() => {
    client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'device-001';
  });

  it('group.add_member 返回 error 时不应触发密钥分发', async () => {
    // 模拟 transport.call 返回错误结果
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      error: { code: -33003, message: 'not authorized' },
    });

    const distributeSpy = vi.spyOn(client as any, '_distributeKeyToNewMember').mockResolvedValue(undefined);
    const rotateSpy = vi.spyOn(client as any, '_rotateGroupEpoch').mockResolvedValue(undefined);

    await client.call('group.add_member', {
      group_id: 'group-123',
      aid: 'new-member.aid.com',
    });

    // 失败的 add_member 不应触发密钥分发
    expect(distributeSpy).not.toHaveBeenCalled();
    expect(rotateSpy).not.toHaveBeenCalled();
  });

  it('group.add_member 成功时应触发密钥分发', async () => {
    // 模拟成功结果
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      ok: true,
    });

    const distributeSpy = vi.spyOn(client as any, '_distributeKeyToNewMember').mockResolvedValue(undefined);

    await client.call('group.add_member', {
      group_id: 'group-123',
      aid: 'new-member.aid.com',
    });

    // 成功的 add_member 应触发密钥分发
    expect(distributeSpy).toHaveBeenCalledWith('group-123', 'new-member.aid.com');
  });
});

// ── JS-012: _buildRotationSignature 不应使用动态 import ──────────

describe('JS-012: _buildRotationSignature 不应使用冗余动态 import', () => {
  it('源码中 _buildRotationSignature 不应包含动态 import("./crypto")', async () => {
    // 读取 _buildRotationSignature 方法源码，确认没有动态 import
    const client = new AUNClient();
    const methodSrc = (client as any)._buildRotationSignature.toString();
    // 修复后不应再包含 import('./crypto 这样的动态导入
    expect(methodSrc).not.toContain("import(");
  });
});

// ── JS-001: off() 事件注销方法 ──────────────────────────────────

describe('JS-001: AUNClient.off() 事件注销方法', () => {
  it('off() 应取消订阅指定的事件处理函数', () => {
    const client = new AUNClient();
    const handler = vi.fn();

    // 先订阅
    client.on('test.event', handler);

    // 再用 off 取消订阅
    client.off('test.event', handler);

    // 手动触发事件，handler 不应被调用
    (client as any)._dispatcher.publish('test.event', { data: 'test' });
    expect(handler).not.toHaveBeenCalled();
  });

  it('off() 只移除指定的 handler，其他 handler 不受影响', () => {
    const client = new AUNClient();
    const handler1 = vi.fn();
    const handler2 = vi.fn();

    client.on('test.event', handler1);
    client.on('test.event', handler2);

    // 仅移除 handler1
    client.off('test.event', handler1);

    (client as any)._dispatcher.publish('test.event', { data: 'test' });
    expect(handler1).not.toHaveBeenCalled();
    expect(handler2).toHaveBeenCalledTimes(1);
  });

  it('off() 对未订阅的事件不应抛错', () => {
    const client = new AUNClient();
    const handler = vi.fn();

    // 对从未订阅的事件调用 off 不应抛异常
    expect(() => client.off('nonexistent.event', handler)).not.toThrow();
  });
});
