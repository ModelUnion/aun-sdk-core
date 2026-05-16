/**
 * 验证 gateway.disconnect 事件 detail 字段透传到应用层。
 *
 * 对齐 Python SDK tests/unit/test_gateway_disconnect_detail.py 的 3 个用例。
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { AUNClient } from '../../src/client.js';

describe('gateway.disconnect detail 透传', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'aun-disc-detail-'));
  });

  // 1. 服务端 event/gateway.disconnect 带 detail 时，应用层订阅者应能拿到。
  it('detail 字段透传到 gateway.disconnect 事件', async () => {
    const client = new AUNClient({ aun_path: tmpDir });
    const received: any[] = [];
    client.on('gateway.disconnect', (data) => { received.push(data); });

    const payload = {
      code: 4015,
      reason: 'long connection quota exceeded: aid_device_slot_quota_exceeded',
      detail: {
        aid: 'alice.example.com',
        device_id: 'dev-1',
        slot_id: 'slot-old',
        limit: 10,
        quota_kind: 'aid_device_slot_quota_exceeded',
        evicted_by: {
          aid: 'alice.example.com',
          device_id: 'dev-1',
          slot_id: 'slot-NEW',
        },
      },
    };
    await (client as any)._onGatewayDisconnect(payload);

    expect(received.length).toBe(1);
    const evt = received[0];
    expect(evt.code).toBe(4015);
    expect(evt.detail.aid).toBe('alice.example.com');
    expect(evt.detail.quota_kind).toBe('aid_device_slot_quota_exceeded');
    expect(evt.detail.evicted_by.slot_id).toBe('slot-NEW');
  });

  // 2. 服务端不带 detail 时，detail 字段应为空对象而不是缺失。
  it('无 detail 时 detail 字段为空对象', async () => {
    const client = new AUNClient({ aun_path: tmpDir });
    const received: any[] = [];
    client.on('gateway.disconnect', (data) => { received.push(data); });

    await (client as any)._onGatewayDisconnect({ code: 4001, reason: 'Auth failed' });

    expect(received.length).toBe(1);
    expect(received[0].code).toBe(4001);
    expect(received[0].detail).toEqual({});
  });

  // 3. 连接进入 terminal_failed 时 connection.state 事件也应带服务端 detail。
  it('terminal_failed 状态变更也带 detail', async () => {
    const client = new AUNClient({ aun_path: tmpDir });
    const states: any[] = [];
    client.on('connection.state', (data) => { states.push(data); });

    // 1. 模拟收到 gateway.disconnect 带 detail
    await (client as any)._onGatewayDisconnect({
      code: 4015,
      reason: 'quota exceeded',
      detail: {
        aid: 'alice.example.com',
        device_id: 'dev-1',
        slot_id: 'slot-x',
        quota_kind: 'aid_device_slot_quota_exceeded',
      },
    });

    // 2. 触发 transport disconnect → 走 terminal_failed 路径
    (client as any)._state = 'connected';
    (client as any)._closing = false;
    (client as any)._reconnectActive = false;
    (client as any)._sessionOptions = {
      auto_reconnect: true,
      heartbeat_interval: 30.0,
      token_refresh_before: 60.0,
      retry: { initial_delay: 1.0, max_delay: 64.0 },
      timeouts: { connect: 5.0, call: 10.0, http: 30.0 },
      connection_kind: 'long',
    };
    await (client as any)._handleTransportDisconnect(null, 4015);

    const terminal = states.filter((s) => s.state === 'terminal_failed');
    expect(terminal.length).toBe(1);
    expect(terminal[0].detail.quota_kind).toBe('aid_device_slot_quota_exceeded');
    expect(terminal[0].code).toBe(4015);
  });
});
