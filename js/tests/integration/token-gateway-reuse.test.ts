/**
 * Token + gateway_url 复用集成测试 — 与 Python integration_test_token_gateway_reuse.py 对齐
 *
 * 浏览器 SDK 模拟 CLI 跨进程场景：
 *   - JS IndexedDB split stores 是全局共享 DB，新建 AUNClient 即等价"重启进程"
 *   - 第一次 authenticate 走完整 discovery + login，token 与 gateway_url 持久化
 *   - 第二次新建 client，authenticate 应直接复用 cached，无网络请求
 *   - cached 过期则回退到完整 _login
 *
 * 覆盖场景（与 Python 一一对齐）：
 *   Test 1: 第一次 authenticate 后 keystore 持久化 access_token + refresh_token + gateway_url
 *   Test 2: 同 aun_path 新建第二个 client，authenticate 时不调用 _login + 不调用 discover
 *   Test 3: 第二个 client 用 cached 直接 connect + meta.ping 成功
 *   Test 4: 手动把 expires_at 改成已过期，第二次 authenticate 应走 _login
 *
 * 前置条件：
 *   - Docker 单域环境运行中（kite-app + kite-mysql）
 *   - agentid.pub / gateway.agentid.pub 解析到本机
 */

import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import * as dns from 'node:dns/promises';
import * as net from 'node:net';
import * as os from 'node:os';
import * as crypto from 'node:crypto';

import { AUNClient } from '../../src/index.js';
import type { IdentityRecord } from '../../src/types.js';
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

function makeClient(): AUNClient {
  const client = new AUNClient();
  ((client as unknown) as { configModel: { requireForwardSecrecy: boolean } }).configModel.requireForwardSecrecy = false;
  return client;
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

describe('Token + gateway_url 复用集成测试', () => {
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

  // ── Test 1: 首次 authenticate 后 keystore 写入 token + gateway_url ────

  it('Test 1: first authenticate persists token + gateway_url', async () => {
    if (skip()) return;

    const aid = `js-tgw-t1-${rid()}.${ISSUER}`;
    const client = makeClient();
    clients.push(client);

    await registerAndLoadIdentity(client, aid);
    const result = await client.authenticate();

    expect(result.access_token).toBeTruthy();
    expect(result.refresh_token).toBeTruthy();

    // 验证 keystore 里写入了 access_token + refresh_token
    const auth = (client as any)._auth;
    const identity = await auth.loadIdentityOrNone(aid) as IdentityRecord | null;
    expect(identity).not.toBeNull();
    expect(identity?.access_token).toBeTruthy();
    expect(identity?.refresh_token).toBeTruthy();

    // 验证 keystore 里持久化了 gateway_url
    const cachedGw = await (client as any)._keystore.getMetadata(aid, 'gateway_url');
    expect(cachedGw).toBeTruthy();
    expect(String(cachedGw)).toMatch(/^wss?:\/\//);
  }, 30000);

  // ── Test 2: 第二次 new client（同 keystore）authenticate 不走网络 ────

  it('Test 2: second authenticate (same keystore) skips _login and discover', async () => {
    if (skip()) return;

    const aid = `js-tgw-t2-${rid()}.${ISSUER}`;

    // 第一次：完整流程
    const client1 = makeClient();
    clients.push(client1);
    await registerAndLoadIdentity(client1, aid);
    const first = await client1.authenticate();
    const firstToken = String(first.access_token ?? '');
    const firstGateway = String(first.gateway ?? '');
    expect(firstToken).toBeTruthy();
    expect(firstGateway).toBeTruthy();
    await client1.close();

    // 第二次：新 client 复用同一 IndexedDB 数据库（模拟 CLI 重启）
    const client2 = makeClient();
    clients.push(client2);
    await loadIdentityFromStore(client2, aid);

    // 拦截 _login（不应被调用）+ discovery（不应被调用）
    const loginSpy = vi.spyOn((client2 as any)._auth, '_login');
    const discoverSpy = vi.spyOn((client2 as any)._discovery, 'discover');

    const second = await client2.authenticate();

    // 验证 token 一致（说明复用，没重新 login）
    expect(second.access_token).toBe(firstToken);

    // 验证 _login 没被调用
    expect(loginSpy).not.toHaveBeenCalled();

    // 验证 discover 没被调用（cached gateway_url 命中）
    expect(discoverSpy).not.toHaveBeenCalled();

    // 验证 gateway 也复用了
    expect(second.gateway).toBe(firstGateway);
  }, 30000);

  // ── Test 3: 复用 cached 直接 connect + RPC 成功 ────────────────────────

  it('Test 3: reused cached token connects and runs meta.ping', async () => {
    if (skip()) return;

    const aid = `js-tgw-t3-${rid()}.${ISSUER}`;

    // 第一次创建 + authenticate
    const client1 = makeClient();
    clients.push(client1);
    await registerAndLoadIdentity(client1, aid);
    await client1.authenticate();
    await client1.close();

    // 第二次：完全重新 new client，复用 keystore，直接 connect
    const client2 = makeClient();
    clients.push(client2);
    await loadIdentityFromStore(client2, aid);
    await client2.connect({ auto_reconnect: false });

    expect(client2.state).toBe('ready');

    const pingResult = await client2.call('meta.ping') as Record<string, unknown>;
    expect(pingResult).toBeTypeOf('object');
  }, 30000);

  // ── Test 4: cached token 过期时 fallback 到完整 _login ────────────────

  it('Test 4: expired cached token falls back to _login', async () => {
    if (skip()) return;

    const aid = `js-tgw-t4-${rid()}.${ISSUER}`;

    // 第一次完整 authenticate
    const client1 = makeClient();
    clients.push(client1);
    await registerAndLoadIdentity(client1, aid);
    const first = await client1.authenticate();
    const firstToken = String(first.access_token ?? '');
    expect(firstToken).toBeTruthy();
    await client1.close();

    // 手动把 keystore 里的 expires_at 改成已过期
    const editor = makeClient();
    clients.push(editor);
    const editorAuth = (editor as any)._auth;
    const identity = await editorAuth.loadIdentityOrNone(aid) as IdentityRecord | null;
    expect(identity).not.toBeNull();
    if (identity) {
      identity.access_token_expires_at = Math.floor(Date.now() / 1000) - 100; // 100s 前过期
      await editorAuth._persistIdentity(identity);
    }
    await editor.close();

    // 第二次：authenticate 应走完整 _login（cached token 已过期）
    const client2 = makeClient();
    clients.push(client2);
    await loadIdentityFromStore(client2, aid);
    const loginSpy = vi.spyOn((client2 as any)._auth, '_login');

    const second = await client2.authenticate();

    // 验证 _login 被调用了
    expect(loginSpy).toHaveBeenCalled();

    // 验证拿到了新 token（不再是过期那个）
    expect(second.access_token).toBeTruthy();
    expect(second.access_token).not.toBe(firstToken);
  }, 30000);
});
