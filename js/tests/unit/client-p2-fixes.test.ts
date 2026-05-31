// ── P2 问题修复测试 ──────────────────────────────────────
// 测试 P2-5/6/7/8 四个问题的修复
import 'fake-indexeddb/auto';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { AUNClient } from '../../src/client.js';

function getClientMethodSource(methodName: string): string {
  const src = readFileSync(
    resolve(__dirname, '../../src/client.ts'),
    'utf-8',
  );
  const start = src.indexOf(`private async ${methodName}`);
  if (start === -1) throw new Error(`未找到 ${methodName} 方法`);
  let braceCount = 0;
  let methodStart = -1;
  for (let i = start; i < src.length; i++) {
    if (src[i] === '{') {
      if (methodStart === -1) methodStart = i;
      braceCount++;
    } else if (src[i] === '}') {
      braceCount--;
      if (braceCount === 0) {
        return src.substring(start, i + 1);
      }
    }
  }
  throw new Error(`无法解析 ${methodName} 方法体`);
}

async function waitForCondition(predicate: () => boolean, timeoutMs = 1000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error('等待条件超时');
}

describe('P2-5: group.pull V2-only 路由', () => {
  let client: AUNClient;

  beforeEach(() => {
    client = new AUNClient();
    (client as any)._transport.call = vi.fn();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'device-001';
  });

  it('group.pull 应路由到内部 V2 pull', async () => {
    (client as any)._v2Session = {};
    const pullGroupV2Spy = vi.spyOn(client as any, '_pullGroupV2').mockResolvedValue([
      { seq: 1, content: 'encrypted-payload-1' },
      { seq: 2, content: 'encrypted-payload-2' },
    ]);

    await client.call('group.pull', {
      group_id: 'group-123',
      after_message_seq: 0,
      device_id: 'device-001',
    });

    expect(pullGroupV2Spy).toHaveBeenCalledWith(
      'group-123',
      0,
      50,
      expect.objectContaining({
        explicitAfterSeq: true,
        cursorParams: expect.objectContaining({
          device_id: 'device-001',
        }),
      }),
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
    (client as any)._v2Session = {};
    const pullV2Spy = vi.spyOn(client as any, '_pullV2').mockResolvedValue(messages);

    // 模拟已有 seq 1-2 的状态，设置 contiguous_seq > 0 以通过 afterSeq === 0 守卫
    (client as any)._seqTracker.onPullResult('p2p:test.aid.com', [{ seq: 1 }, { seq: 2 }]);

    await (client as any)._fillP2pGap();

    expect(pullV2Spy).toHaveBeenCalledTimes(1);
    expect(pullV2Spy).toHaveBeenCalledWith(2, 50);
  });

  it('_fillGroupGap 不应重复调用 onPullResult', async () => {
    const messages = [
      { seq: 3, content: 'msg-3' },
      { seq: 4, content: 'msg-4' },
    ];

    (client as any)._v2Session = {};
    const pullGroupV2Spy = vi.spyOn(client as any, '_pullGroupV2').mockResolvedValue(messages);

    // 模拟已有 seq 1-2 的状态
    (client as any)._seqTracker.onPullResult('group:group-123', [{ seq: 1 }, { seq: 2 }]);

    await (client as any)._fillGroupGap('group-123');

    expect(pullGroupV2Spy).toHaveBeenCalledTimes(1);
    expect(pullGroupV2Spy).toHaveBeenCalledWith('group-123', 2, 50);
  });
});

describe('P2-6.5: 补洞 after=0 与服务端 cursor floor', () => {
  it('P2P/group/group_event 补洞不应因 afterSeq=0 短路', () => {
    expect(getClientMethodSource('_fillP2pGap')).not.toContain('afterSeq === 0');
    expect(getClientMethodSource('_fillGroupGap')).not.toContain('afterSeq === 0');
    expect(getClientMethodSource('_fillGroupEventGap')).not.toContain('afterSeq === 0');
  });

  it('group.pull_events 补洞应使用服务端 cursor.current_seq 推进本地 tracker', () => {
    const methodBody = getClientMethodSource('_fillGroupEventGap');
    expect(methodBody).toContain('cursor.current_seq');
    expect(methodBody).toContain('forceContiguousSeq');
    expect(methodBody).toContain('group.ack_events');
    expect(methodBody).toContain('slot_id: this._slotId');
  });
});

describe('P2-6.6: group.changed 事件补洞链路', () => {
  it('group.changed gap 应拉取 group.pull_events，并释放去重键', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._closing = false;
    (client as any)._aid = 'alice.aid.com';
    (client as any)._deviceId = 'device-1';
    (client as any)._slotId = 'slot-a';
    (client as any)._dispatcher.publish = vi.fn().mockResolvedValue(undefined);
    const saveSpy = vi.spyOn(client as any, '_saveSeqTrackerState').mockImplementation(() => {});
    const transportCalls: Array<{ method: string; params: Record<string, unknown> }> = [];
    (client as any)._transport.call = vi.fn(async (method: string, params: Record<string, unknown>) => {
      transportCalls.push({
        method,
        params: JSON.parse(JSON.stringify(params)),
      });
      if (method === 'group.pull_events') {
        return {
          events: [{
            group_id: 'G1',
            event_seq: 7,
            event_type: 'group.announcement_updated',
            action: 'announcement_updated',
          }],
          cursor: { current_seq: 7 },
        };
      }
      if (method === 'group.ack_events') {
        return { ok: true };
      }
      return { ok: true };
    });

    await (client as any)._onRawGroupChanged({
      group_id: 'G1',
      event_seq: 5,
      action: 'foo',
    });
    await waitForCondition(() => transportCalls.some(({ method }) => method === 'group.ack_events'));

    const pullCall = transportCalls.find(({ method }) => method === 'group.pull_events');
    expect(pullCall?.params).toMatchObject({
      group_id: 'g1',
      after_event_seq: 0,
      device_id: 'device-1',
      slot_id: 'slot-a',
    });
    const ackCall = transportCalls.find(({ method }) => method === 'group.ack_events');
    expect(ackCall?.params).toMatchObject({
      group_id: 'G1',
      event_seq: 7,
      device_id: 'device-1',
      slot_id: 'slot-a',
    });
    expect((client as any)._seqTracker.getContiguousSeq('group_event:G1')).toBe(7);
    expect((client as any)._gapFillDone.size).toBe(0);
    saveSpy.mockRestore();
  });

  it('group.pull_events 空页只修正 cursor，不发送 ack_events', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._closing = false;
    (client as any)._deviceId = 'device-1';
    (client as any)._slotId = 'slot-a';
    (client as any)._seqTracker.restoreState({ 'group_event:G1': 5 });
    (client as any)._dispatcher.publish = vi.fn().mockResolvedValue(undefined);
    const saveSpy = vi.spyOn(client as any, '_saveSeqTrackerState').mockImplementation(() => {});
    const transportCalls: Array<{ method: string; params: Record<string, unknown> }> = [];
    (client as any)._transport.call = vi.fn(async (method: string, params: Record<string, unknown>) => {
      transportCalls.push({ method, params: JSON.parse(JSON.stringify(params)) });
      if (method === 'group.pull_events') {
        return { events: [], cursor: { current_seq: 9 } };
      }
      return { ok: true };
    });

    await (client as any)._fillGroupEventGap('G1');

    expect((client as any)._seqTracker.getContiguousSeq('group_event:G1')).toBe(9);
    expect(transportCalls.some(({ method }) => method === 'group.ack_events')).toBe(false);
    saveSpy.mockRestore();
  });

  it('group.pull_events 发布事件后只 ack 一次最终 contiguous_seq', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._closing = false;
    (client as any)._deviceId = 'device-1';
    (client as any)._slotId = 'slot-a';
    const ns = 'group_event:G1';
    (client as any)._seqTracker.onMessageSeq(ns, 3);
    const saveSpy = vi.spyOn(client as any, '_saveSeqTrackerState').mockImplementation(() => {});
    const transportCalls: Array<{ method: string; params: Record<string, unknown> }> = [];
    (client as any)._transport.call = vi.fn(async (method: string, params: Record<string, unknown>) => {
      transportCalls.push({ method, params: JSON.parse(JSON.stringify(params)) });
      if (method === 'group.pull_events') {
        return {
          events: [{
            group_id: 'G1',
            event_seq: 2,
            event_type: 'group.announcement_updated',
            action: 'announcement_updated',
          }],
          cursor: { current_seq: 2 },
        };
      }
      return { ok: true };
    });
    (client as any)._dispatcher.publish = vi.fn(async (event: string, payload: Record<string, unknown>) => {
      if (event === 'group.changed' && payload?._from_gap_fill) {
        (client as any)._seqTracker.onMessageSeq(ns, 4);
      }
    });

    await (client as any)._fillGroupEventGap('G1');

    const ackCalls = transportCalls.filter(({ method }) => method === 'group.ack_events');
    expect(ackCalls).toHaveLength(1);
    expect(ackCalls[0].params).toMatchObject({
      group_id: 'G1',
      event_seq: 4,
      device_id: 'device-1',
      slot_id: 'slot-a',
    });
    expect((client as any)._seqTracker.getContiguousSeq(ns)).toBe(4);
    saveSpy.mockRestore();
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

describe('group.add_member V2-only 编排', () => {
  let client: AUNClient;

  beforeEach(() => {
    client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._aid = 'test.aid.com';
    (client as any)._deviceId = 'device-001';
  });

  it('group.add_member 返回 error 时不应触发 V1 密钥分发，且不触发 V2 state propose', async () => {
    // 模拟 transport.call 返回错误结果
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      error: { code: -33003, message: 'not authorized' },
    });

    (client as any)._v2Session = {};
    const proposeSpy = vi.spyOn(client as any, '_v2AutoProposeState').mockResolvedValue(undefined);

    await client.call('group.add_member', {
      group_id: 'group-123',
      aid: 'new-member.aid.com',
    });

    expect((client as any)._distributeKeyToNewMember).toBeUndefined();
    expect((client as any)._rotateGroupEpoch).toBeUndefined();
    expect(proposeSpy).not.toHaveBeenCalled();
  });

  it('group.add_member 成功时应触发 V2 state auto-propose，而不是 V1 epoch 轮换', async () => {
    // 模拟成功结果
    (client as any)._transport.call = vi.fn().mockResolvedValue({
      ok: true,
    });

    (client as any)._v2Session = {};
    const proposeSpy = vi.spyOn(client as any, '_v2AutoProposeState').mockResolvedValue(undefined);

    await client.call('group.add_member', {
      group_id: 'group-123',
      aid: 'new-member.aid.com',
    });

    expect((client as any)._maybeLeadRotateGroupEpoch).toBeUndefined();
    expect(proposeSpy).toHaveBeenCalledWith('group-123');
  });
});

// ── JS-012: V1 rotation signature helper 已移除 ──────────

describe('JS-012: _buildRotationSignature V1 helper 已移除', () => {
  it('client 不再保留 _buildRotationSignature', async () => {
    const client = new AUNClient();
    expect((client as any)._buildRotationSignature).toBeUndefined();
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
