/**
 * 长短连接共存集成测试 — 与 Python integration_test_long_short.py 对齐
 *
 * 覆盖场景：
 *   Test 1: 同身份短连接发消息 — RPC 原路返回短连接，bob 收到，alice 长连接无感
 *   Test 2: 短连接不踢长连接（长连接持续在线）
 *   Test 3: 同槽位短连接容量上限 10 → 第 11 个返回 4013
 *   Test 4: short_ttl_ms 兜底 → 服务端 4014 关闭
 *   Test 5: 长连接互踢（同槽位 4009）→ 不影响同槽位短连接
 *   Test 6: 短连接不发布 client.online
 *   Test 7: hello-ok 回包 connection.kind 字段
 *   Test 8: 短连接禁用 token 刷新
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

function rid(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 8);
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function makeSharedPath(tag: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), `aun-ls-${tag}-`));
}

function makeClient(aunPath: string): AUNClient {
  const client = new AUNClient({ aun_path: aunPath });
  ((client as unknown) as { configModel: { requireForwardSecrecy: boolean } }).configModel.requireForwardSecrecy = false;
  return client;
}

async function connectLong(
  client: AUNClient,
  aid: string,
  slotId = 'main',
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
  intervalMs = 300,
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

describe('长短连接共存集成测试', () => {
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

  // ── Test 1: 同身份短连接发消息 ──────────────────────────

  it('Test 1: 同身份短连接发消息 — bob 收到，alice 长连接无感', async () => {
    if (skip()) return;

    const r = rid();
    const aliceAid = `ls-a1-${r}.${ISSUER}`;
    const bobAid = `ls-b1-${r}.${ISSUER}`;

    const alicePath = makeSharedPath('ls1-alice');
    const bobPath = makeSharedPath('ls1-bob');

    const aliceLong = makeClient(alicePath);
    const aliceShort = makeClient(alicePath);
    const bobLong = makeClient(bobPath);
    clients.push(aliceLong, aliceShort, bobLong);

    // 建立长连接
    await connectLong(aliceLong, aliceAid, 'main');
    await connectLong(bobLong, bobAid, 'main');

    // 监听 alice 长连接（不应收到自己发出的消息）
    const aliceUnexpected: unknown[] = [];
    aliceLong.on('message.received', (d: unknown) => aliceUnexpected.push(d));

    // 监听 bob 长连接
    const bobReceived: JsonObject[] = [];
    const text = `cli-to-bob-${r}`;
    let bobResolved = false;
    const bobPromise = new Promise<void>((resolve) => {
      bobLong.on('message.received', (d: unknown) => {
        const data = d as JsonObject;
        const payload = data?.payload as JsonObject | undefined;
        if (payload?.text === text) {
          bobReceived.push(data);
          if (!bobResolved) { bobResolved = true; resolve(); }
        }
      });
    });

    // alice 短连接（同 aid/device/slot）发消息给 bob
    await connectShort(aliceShort, aliceAid, { slot_id: 'main' });
    expect(aliceShort.state).toBe('connected');

    const result = await aliceShort.call('message.send', {
      to: bobAid,
      payload: { type: 'text', text },
    }) as JsonObject;
    // RPC response 原路返回到短连接
    expect(['sent', 'delivered']).toContain(result.status);

    await aliceShort.close();

    // bob 收到消息
    await Promise.race([bobPromise, sleep(10000)]);
    expect(bobReceived.length).toBeGreaterThan(0);

    // alice 长连接无感
    await sleep(2000);
    expect(aliceUnexpected.length).toBe(0);

    // alice 长连接仍正常
    await aliceLong.call('meta.ping');
  }, 30000);

  // ── Test 2: 短连接不踢长连接 ──────────────────────────

  it('Test 2: 短连接进入不踢长连接', async () => {
    if (skip()) return;

    const r = rid();
    const aid = `ls-l2-${r}.${ISSUER}`;
    const sharedPath = makeSharedPath('ls2');

    const longClient = makeClient(sharedPath);
    const shortClient = makeClient(sharedPath);
    clients.push(longClient, shortClient);

    await connectLong(longClient, aid, 'main');

    const longStates: string[] = [];
    longClient.on('connection.state', (d: unknown) => {
      const data = d as JsonObject;
      longStates.push(String(data.state ?? ''));
    });

    // 同 AID 同 slot 起短连接
    await connectShort(shortClient, aid, { slot_id: 'main' });
    await sleep(1000);

    expect(longClient.state).toBe('connected');

    // 短连接能用
    await shortClient.call('meta.ping');
    await shortClient.close();
    await sleep(500);

    // 长连接仍存活
    expect(longClient.state).toBe('connected');
    await longClient.call('meta.ping');
  }, 20000);

  // ── Test 3: 短连接容量上限 → 4013 ──────────────────────

  it('Test 3: 同槽位短连接容量上限 10 → 第 11 个返回 4013', async () => {
    if (skip()) return;

    const r = rid();
    const aid = `ls-c3-${r}.${ISSUER}`;
    const sharedPath = makeSharedPath('ls3');

    const setup = makeClient(sharedPath);
    clients.push(setup);
    await setup.auth.createAid({ aid });
    await setup.close();

    // 起 10 个短连接
    const shorts: AUNClient[] = [];
    for (let i = 0; i < 10; i++) {
      const c = makeClient(sharedPath);
      shorts.push(c);
      clients.push(c);
      await connectShort(c, aid, { slot_id: 'cap' });
    }
    await sleep(500);

    // 第 11 个应被拒
    const overflow = makeClient(sharedPath);
    clients.push(overflow);
    let rejected = false;
    try {
      await connectShort(overflow, aid, { slot_id: 'cap' });
    } catch (err) {
      const msg = String(err);
      if (msg.includes('short_connection_capacity_exceeded') || msg.includes('4013')) {
        rejected = true;
      } else {
        throw err;
      }
    }
    expect(rejected).toBe(true);
  }, 30000);

  // ── Test 4: short_ttl_ms 兜底 → 4014 ──────────────────

  it('Test 4: short_ttl_ms 兜底 — 服务端 ~2s 后关闭', async () => {
    if (skip()) return;

    const r = rid();
    const aid = `ls-t4-${r}.${ISSUER}`;
    const sharedPath = makeSharedPath('ls4');

    const setup = makeClient(sharedPath);
    clients.push(setup);
    await setup.auth.createAid({ aid });
    await setup.close();

    const short = makeClient(sharedPath);
    clients.push(short);
    await connectShort(short, aid, { slot_id: 'ttl', short_ttl_ms: 2000 });
    expect(short.state).toBe('connected');

    // 等待服务端主动关闭
    const evicted = await waitFor(
      () => short.state !== 'connected',
      6000,
    );
    expect(evicted).toBe(true);
  }, 15000);

  // ── Test 5: 长连接互踢，短连接不受影响 ──────────────────

  it('Test 5: 长连接互踢（同槽位 4009），短连接不受影响', async () => {
    if (skip()) return;

    const r = rid();
    const aid = `ls-r5-${r}.${ISSUER}`;
    const sharedPath = makeSharedPath('ls5');

    const setup = makeClient(sharedPath);
    clients.push(setup);
    await setup.auth.createAid({ aid });
    await setup.close();

    const longOld = makeClient(sharedPath);
    const longNew = makeClient(sharedPath);
    clients.push(longOld, longNew);

    await connectLong(longOld, aid, 'slot-x');

    // 3 个短连接
    const shorts: AUNClient[] = [];
    for (let i = 0; i < 3; i++) {
      const c = makeClient(sharedPath);
      shorts.push(c);
      clients.push(c);
      await connectShort(c, aid, { slot_id: 'slot-x' });
    }
    await sleep(500);

    // 新长连接同槽位进入 → 踢旧长连接
    await connectLong(longNew, aid, 'slot-x');
    await sleep(1500);

    expect(longOld.state).not.toBe('connected');
    expect(longNew.state).toBe('connected');

    // 短连接全部仍在线
    for (const c of shorts) {
      expect(c.state).toBe('connected');
      await c.call('meta.ping');
    }
  }, 25000);

  // ── Test 6: 短连接不发布 client.online ──────────────────

  it('Test 6: 短连接不发布 client.online — query_online 应为 offline', async () => {
    if (skip()) return;

    const r = rid();
    const shortOnlyAid = `ls-o6-${r}.${ISSUER}`;
    const observerAid = `ls-q6-${r}.${ISSUER}`;

    const shortPath = makeSharedPath('ls6-short');
    const observerPath = makeSharedPath('ls6-observer');

    const setup = makeClient(shortPath);
    clients.push(setup);
    await setup.auth.createAid({ aid: shortOnlyAid });
    await setup.close();

    const observer = makeClient(observerPath);
    const short = makeClient(shortPath);
    clients.push(observer, short);

    await connectLong(observer, observerAid, 'obs');
    await connectShort(short, shortOnlyAid, { slot_id: 'cli' });
    await sleep(500);

    // observer 查询 short_only_aid 在线状态
    const result = await observer.call('message.query_online', {
      aids: [shortOnlyAid],
    }) as JsonObject;
    const onlineMap = (result?.online ?? {}) as JsonObject;
    const isOnline = Boolean(onlineMap[shortOnlyAid]);
    expect(isOnline).toBe(false);
  }, 20000);

  // ── Test 7: hello-ok 回包 connection.kind ──────────────

  it('Test 7: hello-ok 回包 connection.kind = "short"', async () => {
    if (skip()) return;

    const r = rid();
    const aid = `ls-h7-${r}.${ISSUER}`;
    const sharedPath = makeSharedPath('ls7');

    const setup = makeClient(sharedPath);
    clients.push(setup);
    await setup.auth.createAid({ aid });
    await setup.close();

    const shortClient = makeClient(sharedPath);
    clients.push(shortClient);
    await connectShort(shortClient, aid, { slot_id: 'h7-s' });

    // SDK 的 _sessionOptions 反映回包后的判定
    const sessionOpts = (shortClient as unknown as { _sessionOptions: JsonObject })._sessionOptions;
    expect(sessionOpts.connection_kind).toBe('short');
  }, 15000);

  // ── Test 8: 短连接禁用 token 刷新 ──────────

  it('Test 8: 短连接禁用 heartbeat 与 token 刷新', async () => {
    if (skip()) return;

    const r = rid();
    const aid = `ls-d8-${r}.${ISSUER}`;
    const sharedPath = makeSharedPath('ls8');

    const setup = makeClient(sharedPath);
    clients.push(setup);
    await setup.auth.createAid({ aid });
    await setup.close();

    const short = makeClient(sharedPath);
    clients.push(short);
    await connectShort(short, aid, { slot_id: 'd8' });

    // session_options 应反映短连接
    const sessionOpts = (short as unknown as { _sessionOptions: SessionOptions })._sessionOptions;
    expect(sessionOpts.connection_kind).toBe('short');

    // 短连接生命周期短，不启动 heartbeat
    const heartbeatTimer = (short as unknown as { _heartbeatTimer: unknown })._heartbeatTimer;
    expect(heartbeatTimer).toBeNull();

    // token refresh timer 不应启动
    const tokenRefreshTimer = (short as unknown as { _tokenRefreshTimer: unknown })._tokenRefreshTimer;
    expect(tokenRefreshTimer).toBeNull();
  }, 15000);
});

// 类型辅助（仅用于 as unknown as 断言）
interface SessionOptions {
  auto_reconnect: boolean;
  heartbeat_interval: number;
  connection_kind?: string;
  short_ttl_ms?: number;
  [key: string]: unknown;
}
