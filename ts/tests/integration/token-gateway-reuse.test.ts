/**
 * Token + gateway_url 复用集成测试（同 keystore 跨实例场景）。
 *
 * 与 Python integration_test_token_gateway_reuse.py 对齐：
 *   Test 1: 首次 authenticate 后 keystore 持久化 access_token + refresh_token + gateway_url
 *   Test 2: 同 aun_path 新建第二个 client，authenticate 不调 _login + 不调 discover
 *   Test 3: 第二个 client 用 cached 直接 connect + meta.ping 成功
 *   Test 4: 手动把 expires_at 改成已过期，第二次 authenticate 应走 _login
 *
 * 运行环境（容器内）：
 *   MSYS_NO_PATHCONV=1 docker exec kite-ts-tester bash -lc \
 *     "cd /workspace/ts && npx vitest run tests/integration/token-gateway-reuse.test.ts"
 *
 * 前置条件：
 *   - Docker 单域环境运行中（kite-app + kite-mysql）
 *   - kite-ts-tester 容器内 AUN_DATA_ROOT=/data/aun
 *   - 宿主机若直接跑，本机 DNS 必须把 agentid.pub / gateway.agentid.pub 解析到 127.0.0.1
 *     （否则 dns 解析失败，Gateway 不可达，自动 SKIP）
 */

import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';
import * as dns from 'node:dns/promises';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';

import { AUNClient } from '../../src/client.js';
import type { IdentityRecord, JsonObject } from '../../src/types.js';

process.env.AUN_ENV ??= 'development';

const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';
const AUN_DATA_ROOT = (process.env.AUN_DATA_ROOT ?? '').trim();
const REQUIRED_HOSTS = [ISSUER, `gateway.${ISSUER}`];

// ── 网络可达性探测：DNS 能解析 + 443 能连即可（不强制本机地址） ────

function canConnect(host: string, port: number, timeoutMs: number = 2000): Promise<boolean> {
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

async function hostResolves(host: string): Promise<boolean> {
  try {
    await dns.lookup(host);
    return true;
  } catch {
    return false;
  }
}

async function canReachGateway(): Promise<boolean> {
  const resolveChecks = await Promise.all(REQUIRED_HOSTS.map(h => hostResolves(h)));
  if (resolveChecks.some(ok => !ok)) return false;
  // 443 是 Docker 默认；20001 是 federation 测试映射端口；任一可达即可
  for (const port of [443, 20001]) {
    const checks = await Promise.all(REQUIRED_HOSTS.map(h => canConnect(h, port, 1500)));
    if (checks.every(Boolean)) return true;
  }
  return false;
}

// ── 测试辅助 ───────────────────────────────────────────────────

function rid(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 8);
}

function makeAunPath(tag: string): string {
  const base = AUN_DATA_ROOT
    ? path.join(AUN_DATA_ROOT, 'single-domain', 'persistent', '..')
    : os.tmpdir();
  const root = path.join(base, `ts_token_gw_${tag}_${rid()}`);
  fs.mkdirSync(root, { recursive: true });
  return root;
}

function makeClient(aunPath: string): AUNClient {
  const client = new AUNClient({ aun_path: aunPath }, false);
  ((client as unknown) as {
    _configModel: { requireForwardSecrecy: boolean };
  })._configModel.requireForwardSecrecy = false;
  return client;
}

async function safeClose(client: AUNClient | null | undefined): Promise<void> {
  if (!client) return;
  try {
    await client.close();
  } catch {
    // 测试清理路径不抛异常
  }
}

// ── 测试用例 ───────────────────────────────────────────────────

describe('Token + gateway_url 复用集成测试', () => {
  let canRun = false;
  const clients: AUNClient[] = [];

  beforeAll(async () => {
    canRun = await canReachGateway();
  });

  afterEach(async () => {
    await Promise.allSettled(clients.map(c => safeClose(c)));
    clients.length = 0;
  });

  function shouldSkip(): boolean {
    if (!canRun) {
      console.log(`SKIP: 当前环境无法解析或连接 ${REQUIRED_HOSTS.join(' / ')}（443/20001 端口），用例不具备运行条件`);
      return true;
    }
    return false;
  }

  // ── Test 1: 首次 authenticate 后 keystore 持久化 token + gateway_url ──

  it('Test 1: first authenticate persists token + gateway_url', async () => {
    if (shouldSkip()) return;

    const aid = `tgw-t1-${rid()}.${ISSUER}`;
    const aunPath = makeAunPath('t1');
    const client = makeClient(aunPath);
    clients.push(client);

    await client.auth.registerAid({ aid });
    const result = await client.auth.authenticate({ aid }) as JsonObject;
    expect(String(result.access_token ?? '')).not.toBe('');

    // keystore 持久化了 access_token（注意：access_token 在 instance_state 表里，loadIdentity 会合并）
    const internalAuth = ((client as unknown) as {
      _auth: {
        loadIdentity: (aid?: string) => IdentityRecord;
      };
    })._auth;
    const fullIdentity = internalAuth.loadIdentity(aid);
    expect(String(fullIdentity.access_token ?? '')).not.toBe('');
    expect(String(fullIdentity.refresh_token ?? '')).not.toBe('');

    // keystore 持久化了 gateway_url
    const cachedGw = client.auth._loadCachedGatewayUrl(aid);
    expect(cachedGw).not.toBe('');

    // 校验编码格式：DB 里存的是 JSON 编码（带引号）
    const dbInternal = ((client as unknown) as {
      _keystore: { _getDB?: (aid: string) => { getMetadata: (k: string) => string | null } };
    })._keystore._getDB?.(aid);
    expect(dbInternal).toBeTruthy();
    const rawGw = dbInternal!.getMetadata('gateway_url');
    expect(rawGw).not.toBeNull();
    // 必须是合法 JSON 字符串编码（保证与 saveIdentity 一致）
    expect(() => JSON.parse(String(rawGw))).not.toThrow();
    expect(JSON.parse(String(rawGw))).toBe(cachedGw);
  }, 60_000);

  // ── Test 2: 同 aun_path 第二个 client，authenticate 不调 _login + 不调 discover ──

  it('Test 2: second authenticate (same aun_path) skips network', async () => {
    if (shouldSkip()) return;

    const aid = `tgw-t2-${rid()}.${ISSUER}`;
    const aunPath = makeAunPath('t2');

    // 第一次：完整流程
    const client1 = makeClient(aunPath);
    clients.push(client1);
    await client1.auth.registerAid({ aid });
    const first = await client1.auth.authenticate({ aid }) as JsonObject;
    const firstToken = String(first.access_token ?? '');
    const firstGw = String(first.gateway ?? '');
    await safeClose(client1);
    clients.length = 0;

    // 第二次：新 client 同 aun_path
    const client2 = makeClient(aunPath);
    clients.push(client2);

    const internal2 = (client2 as unknown) as {
      _auth: {
        _login: (gatewayUrl: string, identity: IdentityRecord) => Promise<JsonObject>;
      };
      _discovery: {
        discover: (url: string) => Promise<string>;
      };
    };

    let loginCalls = 0;
    let discoverCalls = 0;

    const originalLogin = internal2._auth._login.bind(internal2._auth);
    internal2._auth._login = async (gatewayUrl: string, identity: IdentityRecord) => {
      loginCalls++;
      return originalLogin(gatewayUrl, identity);
    };

    const originalDiscover = internal2._discovery.discover.bind(internal2._discovery);
    internal2._discovery.discover = async (url: string) => {
      discoverCalls++;
      return originalDiscover(url);
    };

    const second = await client2.auth.authenticate({ aid }) as JsonObject;

    expect(String(second.access_token ?? '')).toBe(firstToken);
    expect(loginCalls).toBe(0);
    expect(discoverCalls).toBe(0);
    expect(String(second.gateway ?? '')).toBe(firstGw);
  }, 90_000);

  // ── Test 3: 复用 cached 直接 connect + meta.ping ───────────────

  it('Test 3: reused cached token connects and runs RPC', async () => {
    if (shouldSkip()) return;

    const aid = `tgw-t3-${rid()}.${ISSUER}`;
    const aunPath = makeAunPath('t3');

    // 第一次完整 authenticate
    const client1 = makeClient(aunPath);
    clients.push(client1);
    await client1.auth.registerAid({ aid });
    await client1.auth.authenticate({ aid });
    await safeClose(client1);
    clients.length = 0;

    // 第二次：完全重新 new client，复用 keystore
    const client2 = makeClient(aunPath);
    clients.push(client2);

    const auth = await client2.auth.authenticate({ aid }) as JsonObject;
    await client2.connect(auth, { auto_reconnect: false });

    expect(client2.state).toBe('connected');

    const pingResult = await client2.call('meta.ping', {});
    expect(pingResult).toBeTruthy();
  }, 90_000);

  // ── Test 4: cached token 过期时回退到完整 _login ──────────────

  it('Test 4: expired cached token falls back to login', async () => {
    if (shouldSkip()) return;

    const aid = `tgw-t4-${rid()}.${ISSUER}`;
    const aunPath = makeAunPath('t4');

    // 第一次完整 authenticate
    const client1 = makeClient(aunPath);
    clients.push(client1);
    await client1.auth.registerAid({ aid });
    const first = await client1.auth.authenticate({ aid }) as JsonObject;
    const firstToken = String(first.access_token ?? '');
    await safeClose(client1);
    clients.length = 0;

    // 手动把 expires_at 改成已过期
    const editor = makeClient(aunPath);
    clients.push(editor);
    const editorAuth = ((editor as unknown) as {
      _auth: {
        loadIdentity: (aid?: string) => IdentityRecord;
        _persistIdentity: (identity: IdentityRecord) => void;
      };
    })._auth;
    const identity = editorAuth.loadIdentity(aid);
    identity.access_token_expires_at = Math.floor(Date.now() / 1000) - 100;
    editorAuth._persistIdentity(identity);
    await safeClose(editor);
    clients.length = 0;

    // 第二次：authenticate 应走完整 _login
    const client2 = makeClient(aunPath);
    clients.push(client2);

    let loginCalls = 0;
    const internal2 = (client2 as unknown) as {
      _auth: {
        _login: (gatewayUrl: string, identity: IdentityRecord) => Promise<JsonObject>;
      };
    };
    const originalLogin = internal2._auth._login.bind(internal2._auth);
    internal2._auth._login = async (gatewayUrl: string, identity: IdentityRecord) => {
      loginCalls++;
      return originalLogin(gatewayUrl, identity);
    };

    const second = await client2.auth.authenticate({ aid }) as JsonObject;

    expect(loginCalls).toBeGreaterThanOrEqual(1);
    expect(String(second.access_token ?? '')).not.toBe(firstToken);
  }, 90_000);
});
