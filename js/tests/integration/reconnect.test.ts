/**
 * 断线重连集成测试 — 需要运行中的 Docker Gateway
 *
 * 通过 Docker 命令模拟真实断线，验证 SDK 自动重连机制。
 * 测试场景与 Python integration_test_reconnect.py 对齐。
 *
 * 注意：JS SDK 为浏览器环境设计，无法直接操作 Docker 命令。
 * 本测试文件保留与 TS SDK 对齐的用例结构，实际执行需在
 * Node.js 环境或通过浏览器自动化框架（Playwright/Cypress）配合外部脚本触发。
 */

import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import * as dns from 'node:dns/promises';
import * as net from 'node:net';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

import { AUNClient } from '../../src/index.js';
import type { JsonObject, Message } from '../../src/types.js';
import { registerAndLoadIdentity } from '../test-support.js';

const DOCKER_COMPOSE_DIR = path.resolve(__dirname, '../../../../docker-deploy');
const execFileAsync = promisify(execFile);
const REQUIRED_LOCAL_HOSTS = ['agentid.pub', 'gateway.agentid.pub'];
process.env.AUN_ENV ??= 'development';
let testMessageSeq = 0;

function nextTestMessageId(prefix = 'js-rc-msg'): string {
  testMessageSeq += 1;
  return `${prefix}-${Date.now().toString(36)}-${testMessageSeq.toString(36)}-${rid()}`;
}

function makeClient(deviceId?: string): AUNClient {
  const client = new AUNClient();
  (client as any).__testAunPath = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-rc-'));
  if (deviceId) {
    (client as unknown as { __testDeviceId: string }).__testDeviceId = deviceId;
  }
  ((client as unknown) as { configModel: { requireForwardSecrecy: boolean } }).configModel.requireForwardSecrecy = false;
  return client;
}

async function ensureConnected(
  client: AUNClient,
  aid: string,
  retry: { maxAttempts?: number; initialDelay?: number; maxDelay?: number } = {},
): Promise<void> {
  await registerAndLoadIdentity(client, aid);
  await client.connect({
    auto_reconnect: true,
    heartbeat_interval: 3,
    call_timeout: 3,
    retry: {
      max_attempts: retry.maxAttempts ?? 10,
      initial_delay: retry.initialDelay ?? 1.0,
      max_delay: retry.maxDelay ?? 10.0,
    },
  });
}

async function dockerCompose(args: string[], timeout: number): Promise<boolean> {
  try {
    await execFileAsync('docker', ['compose', ...args], {
      cwd: DOCKER_COMPOSE_DIR,
      timeout,
      windowsHide: true,
    });
    return true;
  } catch {
    return false;
  }
}

async function dockerRestart(): Promise<boolean> {
  return dockerCompose(['restart', 'kite'], 60000);
}

async function dockerStop(): Promise<boolean> {
  return dockerCompose(['stop', 'kite'], 30000);
}

async function dockerStart(): Promise<boolean> {
  return dockerCompose(['start', 'kite'], 30000);
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function waitFor(predicate: () => boolean, timeoutMs: number = 30000, intervalMs: number = 500): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await sleep(intervalMs);
  }
  return false;
}

async function waitForState(client: AUNClient, state: string, timeoutMs: number = 30000): Promise<boolean> {
  return waitFor(() => client.state === state, timeoutMs);
}

async function waitForRpcReady(client: AUNClient, timeoutMs: number = 30000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (client.state !== 'ready') {
      await sleep(500);
      continue;
    }
    try {
      await client.call('meta.ping');
      return true;
    } catch {
      await sleep(500);
    }
  }
  return false;
}

async function waitForBusinessReady(client: AUNClient, aid: string, timeoutMs: number = 30000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (client.state !== 'ready') {
      await sleep(500);
      continue;
    }
    try {
      await client.call('message.query_online', { aids: [aid] });
      return true;
    } catch (err) {
      await sleep(500);
    }
  }
  return false;
}

async function sendPlainWhenMessageServiceReady(
  client: AUNClient,
  to: string,
  payload: JsonObject,
  timeoutMs = 90000,
): Promise<JsonObject> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown = null;
  while (Date.now() < deadline) {
    if (client.state !== 'ready') {
      await sleep(500);
      continue;
    }
    try {
      return await client.call('message.send', {
        to,
        payload,
        encrypt: false,
        message_id: nextTestMessageId(),
      }) as JsonObject;
    } catch (err) {
      lastError = err;
      const text = err instanceof Error ? err.message : String(err);
      if (!text.includes('no_service') && !text.includes('Service plane unavailable')) {
        throw err;
      }
      await sleep(500);
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError ?? 'message service not ready'));
}

function messagePayloadText(message: unknown): string {
  const payload = (message as { payload?: unknown } | null)?.payload;
  if (typeof payload === 'string') return payload;
  if (payload && typeof payload === 'object') {
    return String((payload as { text?: unknown }).text ?? '');
  }
  return '';
}

async function waitForPulledPayload(
  client: AUNClient,
  text: string,
  timeoutMs = 20000,
): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (client.state !== 'ready') {
      await sleep(500);
      continue;
    }
    try {
      const pullResult = await client.call('message.pull', { after_seq: 0, limit: 100, force: true }) as JsonObject;
      const messages = (pullResult.messages ?? []) as Message[];
      if (messages.some((message) => messagePayloadText(message) === text)) {
        return true;
      }
    } catch {
      await sleep(500);
      continue;
    }
    await sleep(500);
  }
  return false;
}

function localAddresses(): Set<string> {
  const addresses = new Set<string>(['127.0.0.1', '::1']);
  const interfaces = os.networkInterfaces();
  for (const items of Object.values(interfaces)) {
    for (const item of items ?? []) {
      if (item.address) {
        addresses.add(item.address);
      }
    }
  }
  return addresses;
}

const LOCAL_ADDRESSES = localAddresses();

function isLocalAddress(address: string): boolean {
  if (LOCAL_ADDRESSES.has(address)) {
    return true;
  }
  if (address.startsWith('::ffff:')) {
    return LOCAL_ADDRESSES.has(address.slice('::ffff:'.length));
  }
  return false;
}

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

async function hostResolvesToLocalAddress(host: string): Promise<boolean> {
  try {
    const records = await dns.lookup(host, { all: true });
    return records.some(record => isLocalAddress(record.address));
  } catch {
    return false;
  }
}

async function canRunLocalReconnectTest(): Promise<boolean> {
  const resolvedChecks = await Promise.all(REQUIRED_LOCAL_HOSTS.map(host => hostResolvesToLocalAddress(host)));
  if (resolvedChecks.some(ok => !ok)) {
    return false;
  }

  const reachableChecks = await Promise.all(REQUIRED_LOCAL_HOSTS.map(host => canConnect(host, 443)));
  return reachableChecks.every(Boolean);
}

function eventsIncludeDisconnect(states: string[]): boolean {
  return states.includes('standby') || states.includes('reconnecting');
}

async function waitForDisconnectEvent(states: string[], timeoutMs: number): Promise<boolean> {
  return waitFor(() => eventsIncludeDisconnect(states), timeoutMs, 500);
}

const rid = () => Math.random().toString(36).slice(2, 8);

describe('断线重连集成测试', () => {
  let localReconnectReady = false;
  const clients: AUNClient[] = [];

  beforeAll(async () => {
    localReconnectReady = await canRunLocalReconnectTest();
  });

  afterEach(async () => {
    await Promise.allSettled(clients.map(client => client.close()));
    clients.length = 0;
  });

  function shouldSkipLocalReconnect(): boolean {
    if (!localReconnectReady) {
      console.log('SKIP: 宿主机当前未把 agentid.pub / gateway.agentid.pub 解析到本机 443，单域 reconnect 用例不具备运行条件');
      return true;
    }
    return false;
  }

  it('Gateway 重启后自动重连', async () => {
    if (shouldSkipLocalReconnect()) return;

    const r = rid();
    const client = makeClient();
    clients.push(client);
    await ensureConnected(client, `rc-t1-${r}.agentid.pub`, { maxAttempts: 0, maxDelay: 2.0 });
    expect(client.state).toBe('ready');

    const ok = await dockerRestart();
    if (!ok) {
      console.log('SKIP: 无法重启 Gateway');
      return;
    }
    await sleep(15000);

    expect(await waitForRpcReady(client, 90000)).toBe(true);

    const result = await client.call('meta.ping') as JsonObject;
    expect(result).toBeTruthy();
  }, 120000);

  it('状态事件序列：Gateway 重启后至少出现一次断线/重连事件并最终恢复 ready', async () => {
    if (shouldSkipLocalReconnect()) return;

    const r = rid();
    const client = makeClient();
    clients.push(client);
    const states: string[] = [];
    client.on('state_change', (data: unknown) => {
      const payload = data as JsonObject;
      states.push(String(payload.state ?? ''));
    });

    await ensureConnected(client, `rc-t2-${r}.agentid.pub`, { maxAttempts: 0, maxDelay: 2.0 });

    const ok = await dockerRestart();
    if (!ok) {
      console.log('SKIP: 无法重启 Gateway');
      return;
    }
    await sleep(15000);

    const reconnected = await waitForBusinessReady(client, `rc-t2-${r}.agentid.pub`, 90000);
    expect(reconnected).toBe(true);
    expect(eventsIncludeDisconnect(states)).toBe(true);
    expect(states[states.length - 1]).toBe('ready');
  }, 120000);

  it('重连后消息收发正常', async () => {
    if (shouldSkipLocalReconnect()) return;

    const r = rid();
    const alice = makeClient(`rc-a-dev-${r}`);
    const bob = makeClient(`rc-b-dev-${r}`);
    clients.push(alice, bob);
    const aliceAid = `rc-a-${r}.agentid.pub`;
    const bobAid = `rc-b-${r}.agentid.pub`;

    await ensureConnected(alice, aliceAid, { maxAttempts: 0, maxDelay: 2.0 });
    await ensureConnected(bob, bobAid, { maxAttempts: 0, maxDelay: 2.0 });
    expect(await waitForBusinessReady(alice, aliceAid, 90000)).toBe(true);
    expect(await waitForBusinessReady(bob, bobAid, 90000)).toBe(true);

    const ok = await dockerRestart();
    if (!ok) {
      console.log('SKIP: 无法重启 Gateway');
      return;
    }
    await sleep(15000);

    expect(await waitForBusinessReady(alice, aliceAid, 90000)).toBe(true);
    expect(await waitForBusinessReady(bob, bobAid, 90000)).toBe(true);
    await sleep(3000);

    const received: Message[] = [];
    const expectedText = `重连后消息-${r}`;
    const gotMessage = new Promise<void>((resolve) => {
      bob.on('message.received', (msg: unknown) => {
        const m = msg as Message;
        received.push(m);
        const payload = m.payload as JsonObject | undefined;
        if (payload?.text === expectedText) resolve();
      });
    });

    const sendResult = await sendPlainWhenMessageServiceReady(
      alice,
      bobAid,
      { type: 'text', text: expectedText },
    );
    expect(sendResult.message_id).toBeTruthy();

    await Promise.race([gotMessage, sleep(10000)]);
    const pushed = received.some((m) => (m.payload as JsonObject | undefined)?.text === expectedText);
    const pulled = pushed ? true : await waitForPulledPayload(bob, expectedText, 20000);
    expect(pulled).toBe(true);
  }, 120000);

  it('停止 Gateway 后保持自动重连，恢复后重新 ready', async () => {
    if (shouldSkipLocalReconnect()) return;

    const r = rid();
    const client = makeClient();
    clients.push(client);
    const states: string[] = [];
    client.on('state_change', (data: unknown) => {
      const payload = data as JsonObject;
      states.push(String(payload.state ?? ''));
    });

    const aid = `rc-ex-${r}.agentid.pub`;
    await ensureConnected(client, aid, { maxAttempts: 0, maxDelay: 2.0 });

    let stopped = false;
    try {
      const ok = await dockerStop();
      if (!ok) {
        console.log('SKIP: 无法停止 Gateway');
        return;
      }
      stopped = true;

      const sawDisconnectEvent = await waitForDisconnectEvent(states, 20000);
      expect(sawDisconnectEvent).toBe(true);
      expect(eventsIncludeDisconnect(states)).toBe(true);
      expect(['standby', 'retry_backoff', 'reconnecting', 'connecting']).toContain(client.state);

      const started = await dockerStart();
      expect(started).toBe(true);
      stopped = false;

      const reconnected = await waitForBusinessReady(client, aid, 90000);
      expect(reconnected).toBe(true);
    } finally {
      if (stopped) {
        await dockerStart();
      }
    }
  }, 120000);
});
