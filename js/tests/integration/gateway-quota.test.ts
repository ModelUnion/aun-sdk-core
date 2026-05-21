/**
 * Gateway 长连接配额 + 短连接空闲 TTL 集成测试
 *
 * 与 Python tests/unit/test_gateway_disconnect_detail.py +
 *    extensions/services/codex-unit/gateway/test_gateway_quota.py 对齐。
 *
 * 覆盖场景：
 *   Test 1: (aid, device) 下 slot 数超限 → close 4015 +
 *           quota_kind=aid_device_slot_quota_exceeded
 *   Test 2: aid 下 device 数超限 → close 4015 +
 *           quota_kind=aid_devices_quota_exceeded
 *   Test 3: device 下 aid 数超限 → close 4015 +
 *           quota_kind=device_aids_quota_exceeded
 *   Test 4: 短连接空闲 TTL 滑动窗口 — 不保活则被关闭，持续 RPC 保活则不关闭
 *
 * 服务端：
 *   - GATEWAY_LONG_SLOTS_PER_AID_DEVICE 默认 10
 *   - GATEWAY_LONG_DEVICES_PER_AID       默认 10
 *   - GATEWAY_LONG_AIDS_PER_DEVICE       默认 10
 *
 * 前置条件：
 *   - Docker 单域环境运行中（kite-app + kite-mysql）
 *   - agentid.pub / gateway.agentid.pub 解析到本机
 */

import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import * as dns from 'node:dns/promises';
import * as net from 'node:net';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

import { AUNClient } from '../../src/index.js';
import type { JsonObject } from '../../src/types.js';

const REQUIRED_LOCAL_HOSTS = ['agentid.pub', 'gateway.agentid.pub'];
process.env.AUN_ENV ??= 'development';

const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';

// 服务端默认配额（与 GATEWAY_LONG_*_PER_* 对齐）
const SLOTS_PER_AID_DEVICE = Number(process.env.GATEWAY_LONG_SLOTS_PER_AID_DEVICE ?? 10);
const DEVICES_PER_AID = Number(process.env.GATEWAY_LONG_DEVICES_PER_AID ?? 10);
const AIDS_PER_DEVICE = Number(process.env.GATEWAY_LONG_AIDS_PER_DEVICE ?? 10);

function rid(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 8);
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function makeSharedPath(tag: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), `aun-q-${tag}-`));
}

function makeClient(aunPath: string, deviceId?: string): AUNClient {
  const client = new AUNClient({ aun_path: aunPath });
  ((client as unknown) as { configModel: { requireForwardSecrecy: boolean } }).configModel.requireForwardSecrecy = false;
  if (deviceId) {
    // jsdom 下所有 client 共享 localStorage，默认 _deviceId 相同；
    // 这里直接覆写 _deviceId，模拟不同设备。
    (client as unknown as { _deviceId: string })._deviceId = deviceId;
  }
  return client;
}

interface CapturedDisconnect {
  code?: number;
  reason?: string;
  detail?: Record<string, unknown>;
}

function captureDisconnect(client: AUNClient): {
  events: CapturedDisconnect[];
  states: Array<{ state: string; code?: number; detail?: Record<string, unknown> }>;
} {
  const events: CapturedDisconnect[] = [];
  const states: Array<{ state: string; code?: number; detail?: Record<string, unknown> }> = [];
  client.on('gateway.disconnect', (data: unknown) => {
    const d = (data ?? {}) as CapturedDisconnect;
    events.push(d);
  });
  client.on('connection.state', (data: unknown) => {
    const d = (data ?? {}) as { state?: string; code?: number; detail?: Record<string, unknown> };
    if (d.state) {
      states.push({ state: String(d.state), code: d.code, detail: d.detail });
    }
  });
  return { events, states };
}

async function connectLong(
  client: AUNClient,
  aid: string,
  slotId: string,
): Promise<void> {
  await client.auth.createAid({ aid });
  const auth = await client.auth.authenticate({ aid });
  await client.connect(auth, {
    auto_reconnect: false,
    heartbeat_interval: 30,
    slot_id: slotId,
  });
}

async function connectShort(
  client: AUNClient,
  aid: string,
  opts: { slot_id?: string; short_ttl_ms?: number } = {},
): Promise<void> {
  await client.auth.createAid({ aid });
  const auth = await client.auth.authenticate({ aid });
  await client.connect(auth, {
    connection_kind: 'short',
    auto_reconnect: false,
    slot_id: opts.slot_id ?? 'main',
    ...(opts.short_ttl_ms ? { short_ttl_ms: opts.short_ttl_ms } : {}),
  });
}

async function waitFor(
  predicate: () => boolean,
  timeoutMs = 15000,
  intervalMs = 200,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await sleep(intervalMs);
  }
  return false;
}

function disconnectedWithCode(captured: { events: CapturedDisconnect[] }, code: number): boolean {
  return captured.events.some((event) => event.code === code);
}

// ── 环境检测 ──────────────────────────────────────

function localAddresses(): Set<string> {
  const addresses = new Set<string>(['127.0.0.1', '::1']);
  const interfaces = os.networkInterfaces();
  for (const items of Object.values(interfaces)) {
    for (const item of items ?? []) {
      if (item.address) addresses.add(item.address);
    }
  }
  return addresses;
}

const LOCAL_ADDRESSES = localAddresses();

function isLocalAddress(address: string): boolean {
  if (LOCAL_ADDRESSES.has(address)) return true;
  if (address.startsWith('::ffff:')) {
    return LOCAL_ADDRESSES.has(address.slice('::ffff:'.length));
  }
  return false;
}

function canConnect(host: string, port: number, timeoutMs = 2000): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    const finish = (ok: boolean): void => {
      socket.removeAllListeners();
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
  });
}

async function canRunTest(): Promise<boolean> {
  for (const host of REQUIRED_LOCAL_HOSTS) {
    try {
      const records = await dns.lookup(host, { all: true });
      if (!records.some(r => isLocalAddress(r.address))) return false;
    } catch {
      return false;
    }
  }
  const reachable = await Promise.all(REQUIRED_LOCAL_HOSTS.map(h => canConnect(h, 443)));
  return reachable.every(Boolean);
}

// ── 测试 ──────────────────────────────────────────

describe('Gateway 长连接配额 + 短连接空闲 TTL 集成测试', () => {
  let ready = false;
  const clients: AUNClient[] = [];

  beforeAll(async () => {
    ready = await canRunTest();
  });

  afterEach(async () => {
    await Promise.allSettled(clients.map(c => c.close()));
    clients.length = 0;
  });

  function skip(): boolean {
    if (!ready) {
      console.log('SKIP: agentid.pub / gateway.agentid.pub 未解析到本机或 Gateway 不可达');
      return true;
    }
    return false;
  }

  // ── Test 1: (aid, device) 下 slot 数超限 ──────────────────────

  it('Test 1: (aid, device) → slot 配额超限 触发 4015 + aid_device_slot_quota_exceeded', async () => {
    if (skip()) return;

    const r = rid();
    const aid = `q-s1-${r}.${ISSUER}`;
    const sharedPath = makeSharedPath('s1');
    const deviceId = `q-s1-dev-${r}`;

    // 占满 SLOTS_PER_AID_DEVICE 个 slot（同 aid + 同 device）
    const filled: AUNClient[] = [];
    for (let i = 0; i < SLOTS_PER_AID_DEVICE; i++) {
      const c = makeClient(sharedPath, deviceId);
      filled.push(c);
      clients.push(c);
      await connectLong(c, aid, `slot-${i}`);
      await sleep(150);
    }
    await sleep(500);

    // 监听最早连接（即将被踢）
    const oldest = filled[0];
    const captured = captureDisconnect(oldest);

    // 第 SLOTS+1 个新 slot 进入 → 服务端踢最早的（slot-0）
    const overflow = makeClient(sharedPath, deviceId);
    clients.push(overflow);
    await connectLong(overflow, aid, `slot-new-${r}`);

    // 等待最早连接收到 4015；auto_reconnect=false 时状态可能停在 disconnected
    const kicked = await waitFor(() => disconnectedWithCode(captured, 4015), 10000);
    expect(kicked).toBe(true);

    // gateway.disconnect 事件包含 4015 + 配额信息
    expect(captured.events.length).toBeGreaterThan(0);
    const evt = captured.events[0];
    expect(evt.code).toBe(4015);
    expect(evt.detail).toBeDefined();
    expect(evt.detail!.quota_kind).toBe('aid_device_slot_quota_exceeded');
    expect(evt.detail!.aid).toBe(aid);
    expect(evt.detail!.device_id).toBe(deviceId);
    expect(evt.detail!.slot_id).toBe('slot-0');
    const evictedBy = evt.detail!.evicted_by as JsonObject | undefined;
    expect(evictedBy).toBeDefined();
    expect(evictedBy!.slot_id).toBe(`slot-new-${r}`);

    // 如果 SDK 进入 terminal_failed，connection.state 也应带 detail；auto_reconnect=false 时不会进入该状态。
    const terminal = captured.states.find(s => s.state === 'terminal_failed');
    if (terminal) {
      expect(terminal.code).toBe(4015);
      expect(terminal.detail).toBeDefined();
      expect((terminal.detail as JsonObject).quota_kind).toBe('aid_device_slot_quota_exceeded');
    }

    // 新连接和其他未被踢的连接仍正常
    expect(overflow.state).toBe('connected');
    await overflow.call('meta.ping');
  }, 60000);

  // ── Test 2: aid 下 device 数超限 ──────────────────────

  it('Test 2: aid → device 配额超限 触发 4015 + aid_devices_quota_exceeded', async () => {
    if (skip()) return;

    const r = rid();
    const aid = `q-d2-${r}.${ISSUER}`;
    const sharedPath = makeSharedPath('s2');

    // 占满 DEVICES_PER_AID 个 device（同 aid，不同 device_id）
    const filled: AUNClient[] = [];
    for (let i = 0; i < DEVICES_PER_AID; i++) {
      const c = makeClient(sharedPath, `q-d2-dev-${i}-${r}`);
      filled.push(c);
      clients.push(c);
      await connectLong(c, aid, 'main');
      await sleep(150);
    }
    await sleep(500);

    // 监听最早 device 上的连接（即将被踢）
    const oldest = filled[0];
    const captured = captureDisconnect(oldest);

    // 第 DEVICES+1 个新 device 进入 → 服务端踢最早 device 的所有连接
    const newDeviceClient = makeClient(sharedPath, `q-d2-dev-new-${r}`);
    clients.push(newDeviceClient);
    await connectLong(newDeviceClient, aid, 'main');

    // 最早 device 上的连接被踢
    const kicked = await waitFor(() => disconnectedWithCode(captured, 4015), 10000);
    expect(kicked).toBe(true);

    expect(captured.events.length).toBeGreaterThan(0);
    const evt = captured.events[0];
    expect(evt.code).toBe(4015);
    expect(evt.detail!.quota_kind).toBe('aid_devices_quota_exceeded');
    expect(evt.detail!.aid).toBe(aid);
    expect(evt.detail!.device_id).toBe(`q-d2-dev-0-${r}`);
    const evictedBy = evt.detail!.evicted_by as JsonObject | undefined;
    expect(evictedBy!.device_id).toBe(`q-d2-dev-new-${r}`);

    // 新连接仍正常
    expect(newDeviceClient.state).toBe('connected');
    await newDeviceClient.call('meta.ping');
  }, 60000);

  // ── Test 3: device 下 aid 数超限 ──────────────────────

  it('Test 3: device → aid 配额超限 触发 4015 + device_aids_quota_exceeded', async () => {
    if (skip()) return;

    const r = rid();
    const sharedDevice = `q-a3-dev-${r}`;
    const sharedPath = makeSharedPath('s3');

    // 占满 AIDS_PER_DEVICE 个 aid（同 device，不同 aid）
    const filled: AUNClient[] = [];
    const aids: string[] = [];
    for (let i = 0; i < AIDS_PER_DEVICE; i++) {
      const aid = `q-a3-${i}-${r}.${ISSUER}`;
      aids.push(aid);
      const c = makeClient(sharedPath, sharedDevice);
      filled.push(c);
      clients.push(c);
      await connectLong(c, aid, 'main');
      await sleep(150);
    }
    await sleep(500);

    // 监听最早 aid 的连接（即将被踢）
    const oldest = filled[0];
    const captured = captureDisconnect(oldest);

    // 第 AIDS+1 个新 aid 在同 device 上进入
    const newAid = `q-a3-new-${r}.${ISSUER}`;
    const newAidClient = makeClient(sharedPath, sharedDevice);
    clients.push(newAidClient);
    await connectLong(newAidClient, newAid, 'main');

    const kicked = await waitFor(() => disconnectedWithCode(captured, 4015), 10000);
    expect(kicked).toBe(true);

    expect(captured.events.length).toBeGreaterThan(0);
    const evt = captured.events[0];
    expect(evt.code).toBe(4015);
    expect(evt.detail!.quota_kind).toBe('device_aids_quota_exceeded');
    expect(evt.detail!.aid).toBe(aids[0]);
    expect(evt.detail!.device_id).toBe(sharedDevice);
    const evictedBy = evt.detail!.evicted_by as JsonObject | undefined;
    expect(evictedBy!.aid).toBe(newAid);

    expect(newAidClient.state).toBe('connected');
    await newAidClient.call('meta.ping');
  }, 60000);

  // ── Test 4: 短连接空闲 TTL 滑动窗口（保活 vs 不保活）──────

  it('Test 4: 短连接 short_ttl_ms 滑动窗口 — 不保活被关闭，保活不关闭', async () => {
    if (skip()) return;

    const ttl = 1500; // 1.5s

    // 4a. 不保活：建立后空闲，应被服务端 4014 关闭
    {
      const r = rid();
      const aid = `q-t4a-${r}.${ISSUER}`;
      const sharedPath = makeSharedPath('s4a');
      const idleClient = makeClient(sharedPath);
      clients.push(idleClient);

      const captured = captureDisconnect(idleClient);
      await connectShort(idleClient, aid, { slot_id: 'idle', short_ttl_ms: ttl });
      expect(idleClient.state).toBe('connected');

      // 空闲等待超过 ttl
      const closed = await waitFor(() => idleClient.state !== 'connected', ttl + 4000);
      expect(closed).toBe(true);
      // 关闭原因为 short_idle_ttl
      const evt = captured.events.find(e => e.code === 4014);
      expect(evt).toBeDefined();
      expect(evt!.detail).toBeDefined();
      expect(typeof (evt!.detail as JsonObject).idle_ms).toBe('number');
    }

    // 4b. 保活：每 < ttl 时间发一次 RPC，连接应持续存活
    {
      const r = rid();
      const aid = `q-t4b-${r}.${ISSUER}`;
      const sharedPath = makeSharedPath('s4b');
      const aliveClient = makeClient(sharedPath);
      clients.push(aliveClient);

      const captured = captureDisconnect(aliveClient);
      await connectShort(aliveClient, aid, { slot_id: 'alive', short_ttl_ms: ttl });
      expect(aliveClient.state).toBe('connected');

      // 持续 ~3 倍 ttl，每 ttl/3 发一次 ping 保活
      const total = ttl * 3;
      const interval = Math.floor(ttl / 3);
      const deadline = Date.now() + total;
      while (Date.now() < deadline) {
        await aliveClient.call('meta.ping');
        await sleep(interval);
      }

      // 期间不应被服务端关闭
      expect(aliveClient.state).toBe('connected');
      const idleEvt = captured.events.find(e => e.code === 4014);
      expect(idleEvt).toBeUndefined();
    }
  }, 60000);
});
