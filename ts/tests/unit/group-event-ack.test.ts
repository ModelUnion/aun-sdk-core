/**
 * 群事件推送路径 ack 测试 — ISSUE-TS-002
 * 验证群事件组件在处理 event_seq 后发送 ack 并持久化状态
 *
 * 私有主类方法已拆成 shim，源码审计应落到 MessageDeliveryEngine 组件。
 */
import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { AUNClient } from '../../src/client.js';

function extractMethodSource(src: string, start: number): string {
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
  throw new Error('无法解析方法体');
}

function getOnRawGroupChangedSource(): string {
  const src = readFileSync(
    resolve(__dirname, '../../src/client.ts'),
    'utf-8',
  );
  // 提取 _onRawGroupChanged 方法体
  const start = src.indexOf('private async _onRawGroupChanged');
  if (start === -1) throw new Error('未找到 _onRawGroupChanged 方法');
  return extractMethodSource(src, start);
}

function getDeliveryMethodSource(methodName: string): string {
  const src = readFileSync(
    resolve(__dirname, '../../src/client/delivery.ts'),
    'utf-8',
  );
  const asyncStart = src.indexOf(`async ${methodName}`);
  const start = asyncStart >= 0 ? asyncStart : src.indexOf(`${methodName}`);
  if (start === -1) throw new Error(`未找到 delivery.${methodName} 方法`);
  return extractMethodSource(src, start);
}

async function waitForCondition(predicate: () => boolean, timeoutMs = 1000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error('等待条件超时');
}

describe('群事件推送路径 ack（ISSUE-TS-002）', () => {
  const mainMethodBody = getOnRawGroupChangedSource();
  const deliveryMethodBody = getDeliveryMethodSource('handleGroupChangedEventSeq');

  it('_onRawGroupChanged 应委托 MessageDeliveryEngine 处理 event_seq', () => {
    expect(mainMethodBody).toContain('_delivery.handleGroupChangedEventSeq');
  });

  it('event_seq 处理后应调用 _saveSeqTrackerState 持久化', () => {
    expect(deliveryMethodBody).toContain('this.persistSeq(ns)');
  });

  it('event_seq 处理后应发送 group.ack_events', () => {
    expect(deliveryMethodBody).toContain('group.ack_events');
  });
});

describe('补洞 after=0 与服务端 cursor floor', () => {
  it('P2P/group/group_event 补洞不应因 afterSeq=0 短路', () => {
    expect(getDeliveryMethodSource('fillP2pGap')).not.toContain('afterSeq === 0');
    expect(getDeliveryMethodSource('fillGroupGap')).not.toContain('afterSeq === 0');
    expect(getDeliveryMethodSource('fillGroupEventGap')).not.toContain('afterSeq === 0');
  });

  it('group.pull_events 补洞应使用服务端 cursor.current_seq 推进本地 tracker', () => {
    const methodBody = getDeliveryMethodSource('fillGroupEventGap');
    expect(methodBody).toContain('cursor.current_seq');
    expect(methodBody).toContain('forceContiguousSeq');
    expect(methodBody).toContain('group.ack_events');
    expect(methodBody).toContain('_gapFillDone.delete(dedupKey)');
  });
});

describe('group.changed 事件补洞行为', () => {
  it('自己入群首个 event_seq>1 不应被入群前不可见事件阻塞', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._closing = false;
    (client as any)._aid = 'bob1.aid.com';
    (client as any)._deviceId = 'device-1';
    (client as any)._slotId = 'slot-a';
    const saveSpy = vi.spyOn(client as any, '_saveSeqTrackerState').mockImplementation(() => {});
    const transportCalls: Array<{ method: string; params: Record<string, unknown> }> = [];
    (client as any)._transport.call = vi.fn(async (method: string, params: Record<string, unknown>) => {
      transportCalls.push({ method, params: JSON.parse(JSON.stringify(params)) });
      return { ok: true };
    });
    const published: number[] = [];
    client.on('group.changed', (payload: any) => {
      published.push(Number(payload.event_seq));
    });
    const delivery = (client as any)._delivery;
    const fillSpy = vi.spyOn(delivery, 'fillGroupEventGap').mockResolvedValue(undefined);

    await delivery.handleGroupChangedEventSeq({
      group_id: 'g1',
      event_seq: 5,
      action: 'member_added',
      joined_aid: 'bob1.aid.com',
    }, 'g1');
    await waitForCondition(() => transportCalls.some(({ method }) => method === 'group.ack_events'));

    expect(published).toEqual([5]);
    expect((client as any)._seqTracker.getContiguousSeq('group_event:g1')).toBe(5);
    expect(fillSpy).not.toHaveBeenCalled();
    expect(transportCalls.find(({ method }) => method === 'group.ack_events')?.params).toMatchObject({
      group_id: 'g1',
      event_seq: 5,
      device_id: 'device-1',
      slot_id: 'slot-a',
    });
    fillSpy.mockRestore();
    saveSpy.mockRestore();
  });

  it('只带 group_aid 的 group.changed 应使用标准 group_event namespace 并 ack', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._closing = false;
    (client as any)._aid = 'alice.aid.com';
    (client as any)._deviceId = 'device-1';
    (client as any)._slotId = 'slot-a';
    const saveSpy = vi.spyOn(client as any, '_saveSeqTrackerState').mockImplementation(() => {});
    const transportCalls: Array<{ method: string; params: Record<string, unknown> }> = [];
    (client as any)._transport.call = vi.fn(async (method: string, params: Record<string, unknown>) => {
      transportCalls.push({ method, params: JSON.parse(JSON.stringify(params)) });
      return { ok: true };
    });
    const published: number[] = [];
    client.on('group.changed', (payload: any) => {
      published.push(Number(payload.event_seq));
    });

    await (client as any)._onRawGroupChanged({
      group_aid: 'G1',
      event_seq: 1,
      action: 'foo',
    });
    await waitForCondition(() => transportCalls.some(({ method }) => method === 'group.ack_events'));

    expect(published).toEqual([1]);
    expect((client as any)._seqTracker.getContiguousSeq('group_event:g1')).toBe(1);
    expect(transportCalls.find(({ method }) => method === 'group.ack_events')?.params).toMatchObject({
      group_id: 'g1',
      event_seq: 1,
      device_id: 'device-1',
      slot_id: 'slot-a',
    });
    saveSpy.mockRestore();
  });

  it('event_seq gap 应触发 group.pull_events，并用 contiguous_seq + slot_id ack', async () => {
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
      group_id: 'g1',
      event_seq: 7,
      device_id: 'device-1',
      slot_id: 'slot-a',
    });
    expect((client as any)._seqTracker.getContiguousSeq('group_event:g1')).toBe(7);
    expect((client as any)._gapFillDone.size).toBe(0);
    saveSpy.mockRestore();
  });

  it('group.pull_events 空页只修正 cursor，不发送 ack_events', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._closing = false;
    (client as any)._deviceId = 'device-1';
    (client as any)._slotId = 'slot-a';
    (client as any)._seqTracker.restoreState({ 'group_event:g1': 5 });
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

    await (client as any)._delivery.fillGroupEventGap('G1');

    expect((client as any)._seqTracker.getContiguousSeq('group_event:g1')).toBe(9);
    expect(transportCalls.some(({ method }) => method === 'group.ack_events')).toBe(false);
    saveSpy.mockRestore();
  });

  it('group.pull_events 发布事件后只 ack 一次最终 contiguous_seq', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._closing = false;
    (client as any)._deviceId = 'device-1';
    (client as any)._slotId = 'slot-a';
    const ns = 'group_event:g1';
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

    await (client as any)._delivery.fillGroupEventGap('G1');

    const ackCalls = transportCalls.filter(({ method }) => method === 'group.ack_events');
    expect(ackCalls).toHaveLength(1);
    expect(ackCalls[0].params).toMatchObject({
      group_id: 'g1',
      event_seq: 3,
      device_id: 'device-1',
      slot_id: 'slot-a',
    });
    expect((client as any)._seqTracker.getContiguousSeq(ns)).toBe(3);
    saveSpy.mockRestore();
  });

  it('pull 缺失中间 event_seq 时视为永久空洞，不阻塞已拿到的群事件发布', async () => {
    const client = new AUNClient();
    (client as any)._state = 'connected';
    (client as any)._closing = false;
    (client as any)._deviceId = 'device-1';
    (client as any)._slotId = 'slot-a';
    const groupId = 'g1';
    const ns = `group_event:${groupId}`;
    (client as any)._seqTracker.restoreState({ [ns]: 1 });
    const saveSpy = vi.spyOn(client as any, '_saveSeqTrackerState').mockImplementation(() => {});

    const internalConsumed: number[] = [];
    vi.spyOn((client as any)._groupState, 'handleGroupChangedV2Membership').mockImplementation((payload: any) => {
      internalConsumed.push(Number(payload.event_seq));
    });
    const appPublished: number[] = [];
    client.on('group.changed', (payload: any) => {
      appPublished.push(Number(payload.event_seq));
    });

    const delivery = (client as any)._delivery;
    const fillSpy = vi.spyOn(delivery, 'fillGroupEventGap').mockResolvedValue(undefined);
    await delivery.handleGroupChangedEventSeq({
      group_id: groupId,
      event_seq: 5,
      event_type: 'group.member_removed',
      action: 'member_removed',
    }, groupId);
    expect(internalConsumed).toEqual([]);
    expect(appPublished).toEqual([]);
    fillSpy.mockRestore();

    (client as any).call = vi.fn(async (method: string) => {
      if (method === 'group.pull_events') {
        return {
          events: [
            {
              group_id: groupId,
              event_seq: 2,
              event_type: 'group.member_added',
              action: 'member_added',
            },
            {
              group_id: groupId,
              event_seq: 4,
              event_type: 'group.announcement_updated',
              action: 'announcement_updated',
            },
          ],
          cursor: { current_seq: 4 },
          has_more: false,
        };
      }
      return { ok: true };
    });
    const ackCalls: Array<Record<string, unknown>> = [];
    (client as any)._transport.call = vi.fn(async (method: string, params: Record<string, unknown>) => {
      if (method === 'group.ack_events') ackCalls.push(JSON.parse(JSON.stringify(params)));
      return { ok: true };
    });

    await delivery.fillGroupEventGap(groupId);

    expect(internalConsumed).toEqual([2, 4, 5]);
    expect(appPublished).toEqual([2, 4, 5]);
    expect((client as any)._seqTracker.getContiguousSeq(ns)).toBe(5);
    expect(ackCalls).toEqual([{
      group_id: groupId,
      event_seq: 5,
      device_id: 'device-1',
      slot_id: 'slot-a',
    }]);

    await delivery.handleGroupChangedEventSeq({
      group_id: groupId,
      event_seq: 5,
      event_type: 'group.member_removed',
      action: 'member_removed',
    }, groupId);
    expect(internalConsumed).toEqual([2, 4, 5]);
    expect(appPublished).toEqual([2, 4, 5]);
    saveSpy.mockRestore();
  });
});
