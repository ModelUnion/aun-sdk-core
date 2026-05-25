/**
 * 群事件推送路径 ack 测试 — ISSUE-TS-002
 * 验证 _onRawGroupChanged 在处理 event_seq 后发送 ack 并持久化状态
 *
 * 由于 _onRawGroupChanged 是私有方法，通过源码分析验证关键调用存在。
 */
import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { AUNClient } from '../../src/client.js';

function getOnRawGroupChangedSource(): string {
  const src = readFileSync(
    resolve(__dirname, '../../src/client.ts'),
    'utf-8',
  );
  // 提取 _onRawGroupChanged 方法体
  const start = src.indexOf('private async _onRawGroupChanged');
  if (start === -1) throw new Error('未找到 _onRawGroupChanged 方法');
  // 找到方法结束（下一个同级 private/public 方法或类结束）
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
  throw new Error('无法解析 _onRawGroupChanged 方法体');
}

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

describe('群事件推送路径 ack（ISSUE-TS-002）', () => {
  const methodBody = getOnRawGroupChangedSource();

  it('event_seq 处理后应调用 _saveSeqTrackerState 持久化', () => {
    expect(methodBody).toContain('_saveSeqTrackerState');
  });

  it('event_seq 处理后应发送 group.ack_events', () => {
    expect(methodBody).toContain('group.ack_events');
  });
});

describe('补洞 after=0 与服务端 cursor floor', () => {
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
    expect(methodBody).toContain('this._gapFillDone.delete(dedupKey)');
  });
});

describe('group.changed 事件补洞行为', () => {
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
