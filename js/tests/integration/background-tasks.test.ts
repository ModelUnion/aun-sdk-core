/**
 * 后台任务管理集成测试 — 对应 P2-11 修复
 *
 * 验证重连后不重复创建后台任务（心跳、token 刷新等）。
 * 测试场景与 Python integration_test_reconnect.py 中的
 * test_no_duplicate_background_tasks 对齐。
 *
 * 注意：JS SDK 为浏览器环境设计，无法直接操作 Docker 命令。
 * 本测试文件保留与 TS SDK 对齐的用例结构，实际执行需在
 * Node.js 环境或通过浏览器自动化框架配合外部脚本触发。
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
import { registerAndLoadIdentity } from '../test-support.js';
import type { JsonObject } from '../../src/types.js';

const DOCKER_COMPOSE_DIR = path.resolve(__dirname, '../../../../docker-deploy');
const execFileAsync = promisify(execFile);
const REQUIRED_LOCAL_HOSTS = ['agentid.pub', 'gateway.agentid.pub'];
process.env.AUN_ENV ??= 'development';
let testMessageSeq = 0;

function nextTestMessageId(prefix = 'js-bg-msg'): string {
  testMessageSeq += 1;
  return `${prefix}-${Date.now().toString(36)}-${testMessageSeq.toString(36)}-${rid()}`;
}

function makeClient(deviceId?: string): AUNClient {
  const client = new AUNClient();
  (client as any).__testAunPath = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-bg-'));
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
    heartbeat_interval: 5,
    call_timeout: 3,
    retry_max_attempts: retry.maxAttempts ?? 10,
    retry_initial_delay: retry.initialDelay ?? 1.0,
    retry_max_delay: retry.maxDelay ?? 10.0,
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
    } catch {
      await sleep(500);
    }
  }
  return false;
}

async function sendPlainWhenMessageServiceReady(
  client: AUNClient,
  to: string,
  payload: string | JsonObject,
  timeoutMs = 90000,
): Promise<unknown> {
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
      });
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
  let lastError: unknown = null;
  let lastMessageCount = 0;
  let lastPayloads: string[] = [];
  while (Date.now() < deadline) {
    if (client.state !== 'ready') {
      await sleep(500);
      continue;
    }
    try {
      const pullResult = await client.call('message.pull', { after_seq: 0, limit: 100, force: true }) as JsonObject;
      const messages = (pullResult.messages ?? []) as unknown[];
      lastMessageCount = messages.length;
      lastPayloads = messages.map(messagePayloadText).filter(Boolean).slice(-5);
      if (messages.some((message) => messagePayloadText(message) === text)) {
        return true;
      }
    } catch (err) {
      lastError = err;
      await sleep(500);
      continue;
    }
    await sleep(500);
  }
  console.log(
    `DIAG: waitForPulledPayload timeout text=${text} state=${client.state} `
    + `last_count=${lastMessageCount} last_payloads=${JSON.stringify(lastPayloads)} `
    + `last_error=${lastError instanceof Error ? lastError.message : String(lastError ?? '')}`,
  );
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

const rid = () => Math.random().toString(36).slice(2, 8);

describe('后台任务管理集成测试', () => {
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

  it('重连后不重复创建后台任务', async () => {
    if (shouldSkipLocalReconnect()) return;

    const r = rid();
    const client = makeClient();
    clients.push(client);

    await ensureConnected(client, `bg-t1-${r}.agentid.pub`, { maxAttempts: 0, maxDelay: 2.0 });
    expect(client.state).toBe('ready');
    const initialHeartbeatInterval = Number((client as any)._sessionOptions?.heartbeat_interval ?? 0);
    if (!Number.isFinite(initialHeartbeatInterval) || initialHeartbeatInterval <= 0) {
      console.log('SKIP: 当前服务端未下发长连接业务心跳（heartbeat_interval=0），跳过心跳重复创建校验');
      return;
    }

    // 记录初始心跳计数（如果 SDK 暴露）
    const initialHeartbeatCount = (client as any)._heartbeatCount ?? 0;

    // 触发重连
    const ok = await dockerRestart();
    if (!ok) {
      console.log('SKIP: 无法重启 Gateway');
      return;
    }
    await sleep(15000);

    const reconnected = await waitForRpcReady(client, 90000);
    expect(reconnected).toBe(true);

    // 等待至少一次心跳实际发生，再判断增量，避免把固定 sleep 卡在重连时序边界上
    const heartbeatAdvanced = await waitFor(
      () => ((client as any)._heartbeatCount ?? 0) > initialHeartbeatCount,
      20000,
      250,
    );
    expect(heartbeatAdvanced).toBe(true);

    const finalHeartbeatCount = (client as any)._heartbeatCount ?? 0;

    // 验证心跳计数增长正常（约 2 次，允许误差）
    const heartbeatDelta = finalHeartbeatCount - initialHeartbeatCount;
    expect(heartbeatDelta).toBeGreaterThanOrEqual(1);
    expect(heartbeatDelta).toBeLessThanOrEqual(3);
  }, 120000);

  it('重连后消息链恢复验证', async () => {
    if (shouldSkipLocalReconnect()) return;

    const r = rid();
    const alice = makeClient(`bg-a-dev-${r}`);
    const bob = makeClient(`bg-b-dev-${r}`);
    clients.push(alice, bob);
    const aliceAid = `bg-a-${r}.agentid.pub`;
    const bobAid = `bg-b-${r}.agentid.pub`;

    await ensureConnected(alice, aliceAid, { maxAttempts: 0, maxDelay: 2.0 });
    await ensureConnected(bob, bobAid, { maxAttempts: 0, maxDelay: 2.0 });
    expect(await waitForBusinessReady(alice, aliceAid, 90000)).toBe(true);
    expect(await waitForBusinessReady(bob, bobAid, 90000)).toBe(true);

    const received: any[] = [];
    bob.on('message.received', (msg: any) => {
      if (msg?.from === aliceAid) received.push(msg);
    });
    const waitForPayload = (text: string, timeoutMs = 10000): Promise<boolean> => waitFor(
      () => received.some((m) => m?.payload === text || m?.payload?.text === text),
      timeoutMs,
    );

    // 发送第一条消息
    await sendPlainWhenMessageServiceReady(alice, bobAid, 'msg_before_disconnect');
    expect(await waitForPayload('msg_before_disconnect')).toBe(true);

    // 触发重连
    const ok = await dockerRestart();
    if (!ok) {
      console.log('SKIP: 无法重启 Gateway');
      return;
    }
    await sleep(15000);

    expect(await waitForBusinessReady(alice, aliceAid, 90000)).toBe(true);
    expect(await waitForBusinessReady(bob, bobAid, 90000)).toBe(true);
    await sleep(3000);

    // 发送第二条消息（验证消息链恢复）
    const sendResult = await sendPlainWhenMessageServiceReady(alice, bobAid, 'msg_after_reconnect') as JsonObject;
    console.log(`DIAG: msg_after_reconnect send_result=${JSON.stringify(sendResult)}`);
    const pushed = await waitForPayload('msg_after_reconnect');
    const pulled = pushed ? true : await waitForPulledPayload(bob, 'msg_after_reconnect', 60000);
    expect(pulled).toBe(true);
    const payloads = received.map((m: any) => m.payload?.text ?? m.payload);
    expect(payloads).toContain('msg_before_disconnect');
    if (pushed) {
      expect(payloads).toContain('msg_after_reconnect');
    }
  }, 180000);
});
