/**
 * extra_info 集成测试
 *
 * 覆盖场景：
 *   Test 1: 长连接互踢带 extra_info → 被踢方收到 self_extra_info + new_extra_info
 *   Test 2: 不传 extra_info 时向后兼容（正常连接不报错）
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
import { loadIdentityFromStore, registerAndLoadIdentity } from '../test-support.js';

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
  return fs.mkdtempSync(path.join(os.tmpdir(), `aun-ei-${tag}-`));
}

function makeClient(aunPath: string): AUNClient {
  const client = new AUNClient({ aun_path: aunPath });
  ((client as unknown) as { configModel: { requireForwardSecrecy: boolean } }).configModel.requireForwardSecrecy = false;
  return client;
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

describe('extra_info 集成测试', () => {
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

  it('长连接互踢带 extra_info → 被踢方收到 self_extra_info + new_extra_info', async () => {
    if (skip()) return;

    const tag = rid();
    const sharedPath = makePath(tag);
    const aid = `test-ei-${tag}.${ISSUER}`;

    // 第一个客户端连接，带 extra_info
    const client1 = makeClient(sharedPath);
    clients.push(client1);
    await registerAndLoadIdentity(client1, aid);
    const extraInfo1 = { pid: 1001, label: 'client-1' } as unknown as JsonObject;
    await client1.connect({
      auto_reconnect: false,
      heartbeat_interval: 30,
      slot_id: 'main',
      extra_info: extraInfo1,
    });

    // 监听被踢事件
    let disconnectDetail: JsonObject | null = null;
    client1.on('gateway.disconnect', (payload: any) => {
      disconnectDetail = payload?.detail ?? payload ?? null;
    });

    // 第二个客端用同 AID + 同 slot_id 连接 → 踢掉第一个
    const client2 = makeClient(sharedPath);
    clients.push(client2);
    await loadIdentityFromStore(client2, aid);
    const extraInfo2 = { pid: 2002, label: 'client-2' } as unknown as JsonObject;
    await client2.connect({
      auto_reconnect: false,
      heartbeat_interval: 30,
      slot_id: 'main',
      extra_info: extraInfo2,
    });

    // 等待 client1 收到踢人事件
    const received = await waitFor(() => disconnectDetail !== null, 10000);
    expect(received).toBe(true);
    expect(disconnectDetail).not.toBeNull();

    // 验证 self_extra_info 和 new_extra_info
    const detail = disconnectDetail as JsonObject;
    expect(detail.self_extra_info).toEqual(extraInfo1);
    expect(detail.new_extra_info).toEqual(extraInfo2);
  }, 30000);

  it('不传 extra_info 时向后兼容', async () => {
    if (skip()) return;

    const tag = rid();
    const sharedPath = makePath(tag);
    const aid = `test-ei-compat-${tag}.${ISSUER}`;

    // 不传 extra_info 正常连接
    const client1 = makeClient(sharedPath);
    clients.push(client1);
    await registerAndLoadIdentity(client1, aid);
    await client1.connect({
      auto_reconnect: false,
      heartbeat_interval: 30,
      slot_id: 'main',
    });

    // 验证连接成功
    expect(client1.state).toBe('ready');

    // 第二个客户端也不传 extra_info，踢掉第一个
    let disconnectDetail: JsonObject | null = null;
    client1.on('gateway.disconnect', (payload: any) => {
      disconnectDetail = payload?.detail ?? payload ?? null;
    });

    const client2 = makeClient(sharedPath);
    clients.push(client2);
    await loadIdentityFromStore(client2, aid);
    await client2.connect({
      auto_reconnect: false,
      heartbeat_interval: 30,
      slot_id: 'main',
    });

    // 等待踢人事件
    const received = await waitFor(() => disconnectDetail !== null, 10000);
    expect(received).toBe(true);

    // 不传 extra_info 时，detail 中不应有 self_extra_info / new_extra_info
    // 或者为 null/undefined（取决于服务端实现）
    const detail = disconnectDetail as JsonObject;
    const selfInfo = detail.self_extra_info;
    const newInfo = detail.new_extra_info;
    // 向后兼容：要么不存在，要么为 null
    expect(selfInfo == null || (typeof selfInfo === 'object' && Object.keys(selfInfo as object).length === 0)).toBe(true);
    expect(newInfo == null || (typeof newInfo === 'object' && Object.keys(newInfo as object).length === 0)).toBe(true);
  }, 30000);
});
