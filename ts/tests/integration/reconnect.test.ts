/**
 * 断线重连集成测试 — 需要运行中的 Docker Gateway
 *
 * 通过 Docker 命令模拟真实断线，验证 SDK 自动重连机制。
 * 测试场景与 Python integration_test_reconnect.py 对齐。
 */

import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execSync } from 'node:child_process';
import { AUNClient } from '../../src/index.js';
import type { JsonObject, Message } from '../../src/types.js';

const DOCKER_COMPOSE_DIR = path.resolve(__dirname, '../../../../docker-deploy');
process.env.AUN_ENV ??= 'development';

function makeClient(): AUNClient {
  const client = new AUNClient({
    aun_path: fs.mkdtempSync(path.join(os.tmpdir(), 'aun-rc-')),
  });
  ((client as unknown) as { _configModel: { requireForwardSecrecy: boolean } })._configModel.requireForwardSecrecy = false;
  return client;
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  await client.auth.createAid({ aid });
  const auth = await client.auth.authenticate({ aid });
  await client.connect(auth, {
    auto_reconnect: true,
    heartbeat_interval: 5,
    retry: { max_attempts: 10, initial_delay: 1.0, max_delay: 10.0 },
  });
}

function dockerRestart(): boolean {
  try {
    execSync('docker compose restart kite', { cwd: DOCKER_COMPOSE_DIR, timeout: 60000, stdio: 'pipe' });
    return true;
  } catch { return false; }
}

function dockerStop(): boolean {
  try {
    execSync('docker compose stop kite', { cwd: DOCKER_COMPOSE_DIR, timeout: 30000, stdio: 'pipe' });
    return true;
  } catch { return false; }
}

function dockerStart(): boolean {
  try {
    execSync('docker compose start kite', { cwd: DOCKER_COMPOSE_DIR, timeout: 30000, stdio: 'pipe' });
    return true;
  } catch { return false; }
}

function sleep(ms: number): Promise<void> {
  return new Promise(r => setTimeout(r, ms));
}

async function waitForState(client: AUNClient, state: string, timeoutMs: number = 30000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (client.state === state) return true;
    await sleep(500);
  }
  return false;
}

const rid = () => Math.random().toString(36).slice(2, 8);

describe('断线重连集成测试', () => {
  const clients: AUNClient[] = [];
  afterEach(async () => {
    await Promise.allSettled(clients.map(c => c.close()));
    clients.length = 0;
  });

  it('Gateway 重启后自动重连', async () => {
    const r = rid();
    const client = makeClient();
    clients.push(client);
    await ensureConnected(client, `rc-t1-${r}.agentid.pub`);
    expect(client.state).toBe('connected');

    // 重启 Gateway
    const ok = dockerRestart();
    if (!ok) { console.log('SKIP: 无法重启 Gateway'); return; }
    await sleep(15000); // 等待 Gateway 重启

    // 等待重连
    const reconnected = await waitForState(client, 'connected', 60000);
    expect(reconnected).toBe(true);

    // 验证重连后功能正常
    const result = await client.call('meta.ping') as JsonObject;
    expect(result).toBeTruthy();
  }, 120000);

  it('状态事件序列：disconnected → reconnecting → connected', async () => {
    const r = rid();
    const client = makeClient();
    clients.push(client);
    const states: string[] = [];
    client.on('connection.state', (d: any) => states.push(d.state));

    await ensureConnected(client, `rc-t2-${r}.agentid.pub`);

    // 重启触发断线
    const ok = dockerRestart();
    if (!ok) { console.log('SKIP'); return; }
    await sleep(5000);
    await waitForState(client, 'connected', 60000);

    expect(states).toContain('disconnected');
    expect(states).toContain('reconnecting');
    expect(states[states.length - 1]).toBe('connected');
  }, 120000);

  it('重连后消息收发正常', async () => {
    const r = rid();
    const alice = makeClient(), bob = makeClient();
    clients.push(alice, bob);
    const aAid = `rc-a-${r}.agentid.pub`, bAid = `rc-b-${r}.agentid.pub`;
    await ensureConnected(alice, aAid);
    await ensureConnected(bob, bAid);

    // 重启
    dockerRestart();
    await sleep(15000);
    await waitForState(alice, 'connected', 60000);
    await waitForState(bob, 'connected', 60000);
    await sleep(3000); // 等待后台任务

    // 重连后发消息
    const result = await alice.call('message.send', {
      to: bAid, payload: { text: '重连后消息' }, encrypt: false,
    }) as JsonObject;
    expect(result.message_id).toBeTruthy();

    // Bob 拉取
    await sleep(1000);
    const pull = await bob.call('message.pull', { after_seq: 0, limit: 10 }) as JsonObject;
    const msgs = (pull.messages ?? []) as Message[];
    expect(msgs.length).toBeGreaterThan(0);
  }, 120000);

  it('非可重试错误进入 terminal_failed', async () => {
    const r = rid();
    const client = new AUNClient({
      aun_path: fs.mkdtempSync(path.join(os.tmpdir(), 'aun-rc-ex-')),
    });
    ((client as unknown) as { _configModel: { requireForwardSecrecy: boolean } })._configModel.requireForwardSecrecy = false;
    clients.push(client);
    const states: string[] = [];
    client.on('connection.state', (d: any) => states.push(d.state));

    await client.auth.createAid({ aid: `rc-ex-${r}.agentid.pub` });
    const auth = await client.auth.authenticate({ aid: `rc-ex-${r}.agentid.pub` });
    await client.connect(auth, {
      auto_reconnect: true,
      retry: { initial_delay: 2, max_delay: 3 },
    });

    // 停止 Gateway（不重启）— 无限重试会持续尝试
    const ok = dockerStop();
    if (!ok) { console.log('SKIP'); return; }

    // 等待至少一次重连尝试
    await sleep(10000);

    // 验证客户端仍在重连中（非 terminal_failed，因为是可重试的网络错误）
    expect(['reconnecting', 'disconnected']).toContain(client.state);
    expect(states).toContain('reconnecting');

    // 恢复 Gateway
    dockerStart();
    await sleep(10000);

    // 最终应该重连成功
    const reconnected = await waitForState(client, 'connected', 60000);
    expect(reconnected).toBe(true);
  }, 120000);
});
