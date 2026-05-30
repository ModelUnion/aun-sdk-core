/**
 * SlotID 前缀隔离集成测试 — 与 Go integration_slot_id_separator_test.go 对齐
 *
 * 覆盖场景：
 *   Test 1: 同前缀互踢 — alice c1(evolclaw cli) + c2(evolclaw daemon) → c1 收到 4009
 *   Test 2: 不同前缀共存 — alice c1(evolclaw cli) + c2(other daemon) → 两者共存
 *   Test 3: P2P 消息路由 — alice daemon 收到 bob 发的消息
 *   Test 4: 非法 slot_id 拒绝 — "/invalid" 被 SDK 校验拒绝
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
import { registerAndLoadIdentity, loadIdentityFromStore } from '../test-support.js';

const REQUIRED_LOCAL_HOSTS = ['agentid.pub', 'gateway.agentid.pub'];
process.env.AUN_ENV ??= 'development';

const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';

function rid(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 8);
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function makePath(tag: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), `aun-sep-${tag}-`));
}

function makeClient(aunPath: string): AUNClient {
  const client = new AUNClient({ aun_path: aunPath });
  ((client as unknown) as { configModel: { requireForwardSecrecy: boolean } }).configModel.requireForwardSecrecy = false;
  return client;
}

interface CapturedDisconnect {
  code?: number;
  reason?: string;
}

function captureDisconnect(client: AUNClient): CapturedDisconnect[] {
  const events: CapturedDisconnect[] = [];
  client.on('gateway.disconnect', (data: unknown) => {
    events.push((data ?? {}) as CapturedDisconnect);
  });
  return events;
}

async function waitFor(
  predicate: () => boolean,
  timeoutMs = 10000,
  intervalMs = 200,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await sleep(intervalMs);
  }
  return false;
}

// ── 环境检测 ──────────────────────────────────────

function localAddresses(): Set<string> {
  const addresses = new Set<string>(['127.0.0.1', '::1']);
  for (const items of Object.values(os.networkInterfaces())) {
    for (const item of items ?? []) {
      if (item.address) addresses.add(item.address);
    }
  }
  return addresses;
}

const LOCAL_ADDRESSES = localAddresses();

function isLocalAddress(address: string): boolean {
  if (LOCAL_ADDRESSES.has(address)) return true;
  if (address.startsWith('::ffff:')) return LOCAL_ADDRESSES.has(address.slice(7));
  return false;
}

function canConnect(host: string, port: number, timeoutMs = 2000): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port });
    const finish = (ok: boolean): void => { socket.removeAllListeners(); socket.destroy(); resolve(ok); };
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

describe('SlotID 前缀隔离集成测试', () => {
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

  // ── Test 1: 同前缀互踢 ──────────────────────────────

  it('Test 1: 同前缀互踢 — c2(evolclaw daemon) 进入后 c1(evolclaw cli) 收到 4009', async () => {
    if (skip()) return;

    const r = rid();
    const aid = `sep-js-${r}.${ISSUER}`;
    const sharedPath = makePath('sep1');

    const c1 = makeClient(sharedPath);
    const c2 = makeClient(sharedPath);
    clients.push(c1, c2);

    const c1Events = captureDisconnect(c1);

    await registerAndLoadIdentity(c1, aid, 'evolclaw cli');
    await c1.connect({ auto_reconnect: false, heartbeat_interval: 30 });
    expect(c1.state).toBe('ready');

    await sleep(200);

    await loadIdentityFromStore(c2, aid, 'evolclaw daemon');
    await c2.connect({ auto_reconnect: false, heartbeat_interval: 30 });
    expect(c2.state).toBe('ready');

    // 等待 c1 收到 4009
    const kicked = await waitFor(() => c1Events.some(e => e.code === 4009), 10000);
    expect(kicked).toBe(true);
    expect(c2.state).toBe('ready');
  }, 30000);

  // ── Test 2: 不同前缀共存 ──────────────────────────────

  it('Test 2: 不同前缀共存 — c1(evolclaw cli) + c2(other daemon) 两者均在线', async () => {
    if (skip()) return;

    const r = rid();
    const aid = `sep-js-${r}.${ISSUER}`;
    const sharedPath = makePath('sep2');

    const c1 = makeClient(sharedPath);
    const c2 = makeClient(sharedPath);
    clients.push(c1, c2);

    const c1Events = captureDisconnect(c1);

    await registerAndLoadIdentity(c1, aid, 'evolclaw cli');
    await c1.connect({ auto_reconnect: false, heartbeat_interval: 30 });
    expect(c1.state).toBe('ready');

    await sleep(200);

    await loadIdentityFromStore(c2, aid, 'other daemon');
    await c2.connect({ auto_reconnect: false, heartbeat_interval: 30 });
    expect(c2.state).toBe('ready');

    // 等待 2 秒确认 c1 未被踢
    await sleep(2000);
    expect(c1Events.some(e => e.code === 4009)).toBe(false);
    expect(c1.state).toBe('ready');
    expect(c2.state).toBe('ready');
  }, 30000);

  // ── Test 3: P2P 消息路由 ──────────────────────────────

  it('Test 3: P2P 消息路由 — alice daemon 收到 bob 发的消息', async () => {
    if (skip()) return;

    const r = rid();
    const aliceAid = `sep-js-a-${r}.${ISSUER}`;
    const bobAid = `sep-js-b-${r}.${ISSUER}`;

    const alicePath = makePath('sep3-alice');
    const bobPath = makePath('sep3-bob');

    const aliceDaemon = makeClient(alicePath);
    const bobClient = makeClient(bobPath);
    clients.push(aliceDaemon, bobClient);

    await registerAndLoadIdentity(aliceDaemon, aliceAid, 'evolclaw daemon');
    await aliceDaemon.connect({ auto_reconnect: false, heartbeat_interval: 30 });
    expect(aliceDaemon.state).toBe('ready');

    await registerAndLoadIdentity(bobClient, bobAid, 'main');
    await bobClient.connect({ auto_reconnect: false, heartbeat_interval: 30 });
    expect(bobClient.state).toBe('ready');

    const text = `hello-daemon-${r}`;
    let received = false;
    const msgPromise = new Promise<void>((resolve) => {
      aliceDaemon.on('message.received', (data: unknown) => {
        const d = data as JsonObject;
        const payload = d?.payload as JsonObject | undefined;
        if (payload?.text === text) { received = true; resolve(); }
      });
    });

    await bobClient.call('message.send', {
      to: aliceAid,
      payload: { type: 'text', text },
      encrypt: false,
    });

    await Promise.race([msgPromise, sleep(10000)]);
    expect(received).toBe(true);
  }, 30000);

  // ── Test 4: 非法 slot_id 拒绝 ──────────────────────────

  it('Test 4: 非法 slot_id "/invalid" 被 SDK 校验拒绝', async () => {
    if (skip()) return;

    const r = rid();
    const aid = `sep-js-${r}.${ISSUER}`;
    const sharedPath = makePath('sep4');
    const client = makeClient(sharedPath);
    clients.push(client);

    // slot_id 来自 AID 对象，/invalid 首字符为 / 应被 normalizeSlotId 拒绝
    await expect(
      registerAndLoadIdentity(client, aid, '/invalid'),
    ).rejects.toThrow();
  }, 30000);
});
