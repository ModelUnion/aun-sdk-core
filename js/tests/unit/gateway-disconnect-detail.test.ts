// ── gateway.disconnect detail 透传测试 ──────────────────────
//
// 对齐 Python 实现（python/src/aun_core/client.py 的 _on_gateway_disconnect / _handle_transport_disconnect）：
// 1) 服务端通过 event/gateway.disconnect 发出的 detail 字段必须透传到应用层 'gateway.disconnect' 事件
// 2) 进入 terminal_failed 路径时，connection.state 事件也要带上 detail/code，便于业务定位被踢原因
import 'fake-indexeddb/auto';
import { describe, it, expect, beforeEach } from 'vitest';
import { AUNClient } from '../../src/client.js';

describe('gateway.disconnect detail 透传', () => {
  let client: AUNClient;

  beforeEach(() => {
    client = new AUNClient();
  });

  it('服务端 disconnect 带 detail → 应用层订阅 gateway.disconnect 拿到完整 detail', async () => {
    const received: any[] = [];
    client.on('gateway.disconnect', (payload) => {
      received.push(payload);
    });

    const evictedBy = { aid: 'bob.example.com', device_id: 'dev-2', slot_id: 'slot-new' };
    const detail = {
      aid: 'alice.example.com',
      device_id: 'dev-1',
      slot_id: 'slot-old',
      quota_kind: 'aid_device_slot_quota_exceeded',
      limit: 10,
      evicted_by: evictedBy,
    };

    // 模拟从 transport 收到 _raw.gateway.disconnect
    await (client as any)._dispatcher.publish('_raw.gateway.disconnect', {
      code: 4015,
      reason: 'long connection quota exceeded: aid_device_slot_quota_exceeded',
      detail,
    });

    expect(received).toHaveLength(1);
    expect(received[0].code).toBe(4015);
    expect(received[0].reason).toBe('long connection quota exceeded: aid_device_slot_quota_exceeded');
    expect(received[0].detail).toEqual(detail);
    expect(received[0].detail.evicted_by).toEqual(evictedBy);
    // _serverKicked 标志同步置位
    expect((client as any)._serverKicked).toBe(true);
    // 缓存写入完整信息
    const cached = (client as any)._lastDisconnectInfo;
    expect(cached).toBeTruthy();
    expect(cached.code).toBe(4015);
    expect(cached.detail).toEqual(detail);
  });

  it('服务端 disconnect 不带 detail → 应用层拿到 detail 为空对象', async () => {
    const received: any[] = [];
    client.on('gateway.disconnect', (payload) => {
      received.push(payload);
    });

    // 不携带 detail 字段
    await (client as any)._dispatcher.publish('_raw.gateway.disconnect', {
      code: 4001,
      reason: 'auth failed',
    });

    expect(received).toHaveLength(1);
    expect(received[0].code).toBe(4001);
    expect(received[0].reason).toBe('auth failed');
    expect(received[0].detail).toEqual({});

    // detail 为非对象（如 null/undefined/字符串）也应规范化为空对象
    received.length = 0;
    await (client as any)._dispatcher.publish('_raw.gateway.disconnect', {
      code: 4003,
      reason: 'forbidden',
      detail: null,
    });
    expect(received).toHaveLength(1);
    expect(received[0].detail).toEqual({});
  });

  it('terminal_failed 状态变更也带 detail（如 4015 配额踢人后）', async () => {
    const states: any[] = [];
    client.on('connection.state', (payload) => {
      states.push(payload);
    });

    const detail = {
      aid: 'alice.example.com',
      device_id: 'dev-1',
      slot_id: 'slot-old',
      quota_kind: 'aid_device_slot_quota_exceeded',
      limit: 10,
      evicted_by: { aid: 'bob.example.com', device_id: 'dev-2', slot_id: 'slot-new' },
    };

    // 1) 先收到服务端 gateway.disconnect 通知，缓存 detail
    await (client as any)._dispatcher.publish('_raw.gateway.disconnect', {
      code: 4015,
      reason: 'long connection quota exceeded',
      detail,
    });

    // 2) 设置成已连接态，让 _handleTransportDisconnect 不会提前 return
    (client as any)._state = 'connected';
    (client as any)._sessionOptions = { ...(client as any)._sessionOptions, auto_reconnect: true };

    // 3) 触发 transport 断开，close code 4015 命中 _NO_RECONNECT_CODES
    const fakeError = new Error('connection closed');
    await (client as any)._handleTransportDisconnect(fakeError, 4015);

    // 应该有两次 connection.state：disconnected 和 terminal_failed
    expect(states.length).toBeGreaterThanOrEqual(2);
    const terminal = states.find((s) => s.state === 'terminal_failed');
    expect(terminal).toBeTruthy();
    expect(terminal.reason).toBeTruthy();
    // detail 必须透传到 terminal_failed 事件
    expect(terminal.detail).toEqual(detail);
    expect(terminal.code).toBe(4015);
  });

  it('terminal_failed 但没有 _lastDisconnectInfo 时事件不带 detail/code 字段', async () => {
    const states: any[] = [];
    client.on('connection.state', (payload) => {
      states.push(payload);
    });

    // 没有发过 gateway.disconnect，直接 close code 4015 触发抑制重连分支
    (client as any)._state = 'connected';
    (client as any)._sessionOptions = { ...(client as any)._sessionOptions, auto_reconnect: true };
    await (client as any)._handleTransportDisconnect(new Error('boom'), 4015);

    const terminal = states.find((s) => s.state === 'terminal_failed');
    expect(terminal).toBeTruthy();
    expect(terminal.detail).toBeUndefined();
    expect(terminal.code).toBeUndefined();
  });
});
