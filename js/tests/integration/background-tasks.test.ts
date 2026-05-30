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

const DOCKER_COMPOSE_DIR = path.resolve(__dirname, '../../../../docker-deploy');
const execFileAsync = promisify(execFile);
const REQUIRED_LOCAL_HOSTS = ['agentid.pub', 'gateway.agentid.pub'];
process.env.AUN_ENV ??= 'development';

function makeClient(): AUNClient {
  const client = new AUNClient({
    aun_path: fs.mkdtempSync(path.join(os.tmpdir(), 'aun-bg-')),
  });
  ((client as unknown) as { configModel: { requireForwardSecrecy: boolean } }).configModel.requireForwardSecrecy = false;
  return client;
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  await registerAndLoadIdentity(client, aid);
  await client.connect({
    auto_reconnect: true,
    heartbeat_interval: 5,
    retry: { max_attempts: 10, initial_delay: 1.0, max_delay: 10.0 },
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

    await ensureConnected(client, `bg-t1-${r}.agentid.pub`);
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

    const reconnected = await waitForState(client, 'ready', 60000);
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
    const alice = makeClient();
    const bob = makeClient();
    clients.push(alice, bob);
    const aliceAid = `bg-a-${r}.agentid.pub`;
    const bobAid = `bg-b-${r}.agentid.pub`;

    await ensureConnected(alice, aliceAid);
    await ensureConnected(bob, bobAid);

    const received: any[] = [];
    bob.on('message.received', (msg: any) => {
      if (msg?.from === aliceAid) received.push(msg);
    });
    const waitForPayload = (text: string, timeoutMs = 10000): Promise<boolean> => waitFor(
      () => received.some((m) => m?.payload === text || m?.payload?.text === text),
      timeoutMs,
    );

    // 发送第一条消息
    await alice.call('message.send', {
      to: bobAid,
      payload: 'msg_before_disconnect',
      encrypt: false,
    });
    expect(await waitForPayload('msg_before_disconnect')).toBe(true);

    // 触发重连
    const ok = await dockerRestart();
    if (!ok) {
      console.log('SKIP: 无法重启 Gateway');
      return;
    }
    await sleep(15000);

    expect(await waitForState(alice, 'ready', 60000)).toBe(true);
    expect(await waitForState(bob, 'ready', 60000)).toBe(true);
    await sleep(3000);

    // 发送第二条消息（验证消息链恢复）
    await alice.call('message.send', {
      to: bobAid,
      payload: 'msg_after_reconnect',
      encrypt: false,
    });
    expect(await waitForPayload('msg_after_reconnect')).toBe(true);
    const payloads = received.map((m: any) => m.payload?.text ?? m.payload);
    expect(payloads).toContain('msg_before_disconnect');
    expect(payloads).toContain('msg_after_reconnect');
  }, 120000);
});
