/**
 * 长短连接 E2E 测试 — 与 Python e2e_test_long_short_cli.py 对齐
 *
 * 核心拓扑：
 *   alice 长连接（daemon，常驻收件箱）+ alice 短连接（CLI，发件）共享同一 (aid, device, slot)。
 *   bob 长连接作为接收方。
 *
 * E2E 场景列表：
 *   E2E 1: CLI 顺序发 5 条消息给 bob — RPC 原路返回短连接，bob 收齐，alice 长连接无感
 *   E2E 2: 5 个并发 CLI 短连接同时发 — 全部成功，bob 收齐
 *   E2E 3: bob 回复 alice — alice 长连接收到入站消息（收件箱功能验证）
 *   E2E 4: CLI 异常退出（ttl 兜底）— alice 长连接不受影响，仍能收 bob 回复
 *   E2E 5: 短连接断开后 alice 长连接仍能收新消息（验证短连接生命周期不影响长连接）
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
  return fs.mkdtempSync(path.join(os.tmpdir(), `aun-e2e-ls-${tag}-`));
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

describe('长短连接 E2E 测试 — 同身份 (aid, device, slot) 共存', () => {
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

  // ── E2E 1: CLI 顺序发 5 条 ──────────────────────────

  it('E2E 1: CLI 顺序发 5 条消息给 bob — bob 收齐，alice 长连接无感', async () => {
    if (skip()) return;

    const r = rid();
    const aliceAid = `e2e1-a-${r}.${ISSUER}`;
    const bobAid = `e2e1-b-${r}.${ISSUER}`;

    const alicePath = makeSharedPath('e1-alice');
    const bobPath = makeSharedPath('e1-bob');

    const aliceLong = makeClient(alicePath);
    const bobLong = makeClient(bobPath);
    clients.push(aliceLong, bobLong);

    await connectLong(aliceLong, aliceAid);
    await connectLong(bobLong, bobAid);

    // alice 长连接监听（不应收到自己发出的消息）
    const aliceUnexpected: unknown[] = [];
    aliceLong.on('message.received', (d: unknown) => aliceUnexpected.push(d));

    // bob 监听
    const bobReceived: JsonObject[] = [];
    const texts = Array.from({ length: 5 }, (_, i) => `e2e1-msg-${i}-${r}`);
    let bobResolved = false;
    const bobPromise = new Promise<void>((resolve) => {
      bobLong.on('message.received', (d: unknown) => {
        const data = d as JsonObject;
        const payload = data?.payload as JsonObject | undefined;
        const txt = String(payload?.text ?? '');
        if (txt.startsWith('e2e1-msg-')) {
          bobReceived.push(data);
          if (bobReceived.length >= 5 && !bobResolved) {
            bobResolved = true;
            resolve();
          }
        }
      });
    });

    // CLI 短连接顺序发 5 条（每次新建短连接，同 aid/device/slot）
    for (const text of texts) {
      const cli = makeClient(alicePath);
      clients.push(cli);
      await connectShort(cli, aliceAid, { slot_id: 'main' });
      const result = await cli.call('message.send', {
        to: bobAid,
        payload: { type: 'text', text },
      }) as JsonObject;
      expect(['sent', 'delivered']).toContain(result.status);
      await cli.close();
    }

    // 验证 bob 收齐
    await Promise.race([bobPromise, sleep(15000)]);
    expect(bobReceived.length).toBeGreaterThanOrEqual(5);

    const receivedTexts = new Set(
      bobReceived.map(m => String((m.payload as JsonObject)?.text ?? '')),
    );
    for (const t of texts) {
      expect(receivedTexts.has(t)).toBe(true);
    }

    // alice 长连接无感
    await sleep(2000);
    expect(aliceUnexpected.length).toBe(0);

    // alice 长连接仍活
    await aliceLong.call('meta.ping');
  }, 60000);

  // ── E2E 2: 5 个并发 CLI 短连接同时发 ──────────────────

  it('E2E 2: 5 个并发 CLI 短连接同时发给 bob — 全部成功', async () => {
    if (skip()) return;

    const r = rid();
    const aliceAid = `e2e2-a-${r}.${ISSUER}`;
    const bobAid = `e2e2-b-${r}.${ISSUER}`;

    const alicePath = makeSharedPath('e2-alice');
    const bobPath = makeSharedPath('e2-bob');

    const aliceLong = makeClient(alicePath);
    const bobLong = makeClient(bobPath);
    clients.push(aliceLong, bobLong);

    await connectLong(aliceLong, aliceAid);
    await connectLong(bobLong, bobAid);

    const bobReceived: JsonObject[] = [];
    let bobResolved = false;
    const bobPromise = new Promise<void>((resolve) => {
      bobLong.on('message.received', (d: unknown) => {
        const data = d as JsonObject;
        const payload = data?.payload as JsonObject | undefined;
        const txt = String(payload?.text ?? '');
        if (txt.startsWith('e2e2-msg-')) {
          bobReceived.push(data);
          if (bobReceived.length >= 5 && !bobResolved) {
            bobResolved = true;
            resolve();
          }
        }
      });
    });

    // 5 个并发短连接（不同 slot 避免容量冲突）
    const sendOne = async (i: number): Promise<JsonObject> => {
      const cli = makeClient(alicePath);
      clients.push(cli);
      await connectShort(cli, aliceAid, { slot_id: `cli-${i}` });
      const result = await cli.call('message.send', {
        to: bobAid,
        payload: { type: 'text', text: `e2e2-msg-${i}-${r}` },
      }) as JsonObject;
      await cli.close();
      return result;
    };

    const results = await Promise.all(
      Array.from({ length: 5 }, (_, i) => sendOne(i)),
    );
    for (const result of results) {
      expect(['sent', 'delivered']).toContain(result.status);
    }

    // bob 收齐
    await Promise.race([bobPromise, sleep(15000)]);
    expect(bobReceived.length).toBeGreaterThanOrEqual(5);
  }, 45000);

  // ── E2E 3: alice 长连接收 bob 回复 ──────────────────────

  it('E2E 3: bob 回复 alice — alice 长连接收到入站消息', async () => {
    if (skip()) return;

    const r = rid();
    const aliceAid = `e2e3-a-${r}.${ISSUER}`;
    const bobAid = `e2e3-b-${r}.${ISSUER}`;

    const alicePath = makeSharedPath('e3-alice');
    const bobPath = makeSharedPath('e3-bob');

    const aliceLong = makeClient(alicePath);
    const bobLong = makeClient(bobPath);
    clients.push(aliceLong, bobLong);

    await connectLong(aliceLong, aliceAid);
    await connectLong(bobLong, bobAid);

    // alice 先用短连接给 bob 发一条
    const cli = makeClient(alicePath);
    clients.push(cli);
    await connectShort(cli, aliceAid);
    await cli.call('message.send', {
      to: bobAid,
      payload: { type: 'text', text: `e2e3-init-${r}` },
    });
    await cli.close();
    await sleep(1000);

    // bob 回复 alice
    const replyText = `e2e3-reply-${r}`;
    let aliceResolved = false;
    const aliceCaptured: JsonObject[] = [];
    const alicePromise = new Promise<void>((resolve) => {
      aliceLong.on('message.received', (d: unknown) => {
        const data = d as JsonObject;
        const payload = data?.payload as JsonObject | undefined;
        if (payload?.text === replyText) {
          aliceCaptured.push(data);
          if (!aliceResolved) { aliceResolved = true; resolve(); }
        }
      });
    });

    const sendResult = await bobLong.call('message.send', {
      to: aliceAid,
      payload: { type: 'text', text: replyText },
    }) as JsonObject;
    expect(['sent', 'delivered']).toContain(sendResult.status);

    await Promise.race([alicePromise, sleep(10000)]);
    expect(aliceCaptured.length).toBeGreaterThan(0);
  }, 30000);

  // ── E2E 4: CLI 崩溃 + ttl 兜底 ──────────────────────────

  it('E2E 4: CLI 崩溃（ttl 兜底）— alice 长连接不受影响，仍收 bob 回复', async () => {
    if (skip()) return;

    const r = rid();
    const aliceAid = `e2e4-a-${r}.${ISSUER}`;
    const bobAid = `e2e4-b-${r}.${ISSUER}`;

    const alicePath = makeSharedPath('e4-alice');
    const bobPath = makeSharedPath('e4-bob');

    const aliceLong = makeClient(alicePath);
    const bobLong = makeClient(bobPath);
    clients.push(aliceLong, bobLong);

    await connectLong(aliceLong, aliceAid);
    await connectLong(bobLong, bobAid);

    // CLI 短连接：建立但不 close（模拟崩溃），ttl=2s
    const cliCrash = makeClient(alicePath);
    clients.push(cliCrash);
    await connectShort(cliCrash, aliceAid, { short_ttl_ms: 2000 });
    expect(cliCrash.state).toBe('connected');

    // 等 ttl 触发
    const evicted = await waitFor(
      () => cliCrash.state !== 'connected',
      6000,
    );
    expect(evicted).toBe(true);

    // alice 长连接仍活
    await aliceLong.call('meta.ping');

    // bob 给 alice 发消息 — alice 长连接应收到
    const replyText = `e2e4-after-crash-${r}`;
    let aliceResolved = false;
    const aliceCaptured: JsonObject[] = [];
    const alicePromise = new Promise<void>((resolve) => {
      aliceLong.on('message.received', (d: unknown) => {
        const data = d as JsonObject;
        const payload = data?.payload as JsonObject | undefined;
        if (payload?.text === replyText) {
          aliceCaptured.push(data);
          if (!aliceResolved) { aliceResolved = true; resolve(); }
        }
      });
    });

    await bobLong.call('message.send', {
      to: aliceAid,
      payload: { type: 'text', text: replyText },
    });

    await Promise.race([alicePromise, sleep(10000)]);
    expect(aliceCaptured.length).toBeGreaterThan(0);
  }, 30000);

  // ── E2E 5: 短连接生命周期后长连接仍收消息 ──────────────

  it('E2E 5: 短连接断开后 alice 长连接仍能收新消息', async () => {
    if (skip()) return;

    const r = rid();
    const aliceAid = `e2e5-a-${r}.${ISSUER}`;
    const bobAid = `e2e5-b-${r}.${ISSUER}`;

    const alicePath = makeSharedPath('e5-alice');
    const bobPath = makeSharedPath('e5-bob');

    const aliceLong = makeClient(alicePath);
    const bobLong = makeClient(bobPath);
    clients.push(aliceLong, bobLong);

    await connectLong(aliceLong, aliceAid);
    await connectLong(bobLong, bobAid);

    // Phase 1: CLI 短连接发消息给 bob
    const cli = makeClient(alicePath);
    clients.push(cli);
    await connectShort(cli, aliceAid);
    const sendResult = await cli.call('message.send', {
      to: bobAid,
      payload: { type: 'text', text: `e2e5-outbound-${r}` },
    }) as JsonObject;
    expect(['sent', 'delivered']).toContain(sendResult.status);
    await cli.close();
    await sleep(1000);

    // Phase 2: bob 回复 alice — alice 长连接应收到
    const replyText = `e2e5-reply-${r}`;
    let aliceResolved = false;
    const aliceCaptured: JsonObject[] = [];
    const alicePromise = new Promise<void>((resolve) => {
      aliceLong.on('message.received', (d: unknown) => {
        const data = d as JsonObject;
        const payload = data?.payload as JsonObject | undefined;
        if (payload?.text === replyText) {
          aliceCaptured.push(data);
          if (!aliceResolved) { aliceResolved = true; resolve(); }
        }
      });
    });

    await bobLong.call('message.send', {
      to: aliceAid,
      payload: { type: 'text', text: replyText },
    });

    await Promise.race([alicePromise, sleep(10000)]);
    expect(aliceCaptured.length).toBeGreaterThan(0);
  }, 30000);
});
