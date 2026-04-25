import { afterEach, describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { AUNClient } from '../../src/client.js';
import type { JsonObject, Message } from '../../src/types.js';

const TEST_TIMEOUT = 150_000;
const MARKER_PATH = String(process.env.AUN_RECONNECT_MARKER ?? '').trim();
process.env.AUN_ENV ??= 'development';

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

function makeClient(tag: string): AUNClient {
  const client = new AUNClient({
    aun_path: fs.mkdtempSync(path.join(os.tmpdir(), `aun-fed-rc-${tag}-`)),
  });
  ((client as unknown) as { _configModel: { requireForwardSecrecy: boolean } })._configModel.requireForwardSecrecy = false;
  return client;
}

async function sleep(ms: number): Promise<void> {
  await new Promise(resolve => setTimeout(resolve, ms));
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    try {
      await client.auth.createAid({ aid });
      const auth = await client.auth.authenticate({ aid });
      await client.connect(auth, {
        auto_reconnect: true,
        heartbeat_interval: 3,
        retry: { initial_delay: 1, max_delay: 5 },
      });
      return;
    } catch (error) {
      lastError = error;
      await client.close().catch(() => undefined);
      if (attempt === 4) {
        throw error;
      }
      await sleep(attempt * 1_000);
    }
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

async function waitFor(
  predicate: () => boolean | Promise<boolean>,
  timeoutMs: number,
  intervalMs: number,
  label: string,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await predicate()) {
      return;
    }
    await new Promise(resolve => setTimeout(resolve, intervalMs));
  }
  throw new Error(`${label} 超时`);
}

async function pullMessages(client: AUNClient, afterSeq = 0, limit = 50): Promise<Message[]> {
  const result = await client.call('message.pull', { after_seq: afterSeq, limit }) as JsonObject;
  return (result.messages ?? []) as Message[];
}

function messageText(message: Message): string {
  const payload = message.payload;
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
    return String((payload as JsonObject).text ?? '');
  }
  return String(payload ?? '');
}

function touchReconnectMarker(): void {
  if (!MARKER_PATH) {
    throw new Error('AUN_RECONNECT_MARKER 未设置');
  }
  fs.writeFileSync(MARKER_PATH, 'ready', 'utf-8');
}

async function waitForFederationDelivery(
  alice: AUNClient,
  bob: AUNClient,
  aliceAid: string,
  bobAid: string,
  rid: string,
): Promise<void> {
  let attempt = 0;
  await waitFor(
    async () => {
      attempt += 1;
      const text = `ts reconnect hello ${rid}-${attempt}`;
      try {
        const sendResult = await alice.call('message.send', {
          to: bobAid,
          payload: { type: 'text', text },
          encrypt: false,
        }) as JsonObject;
        if (!(sendResult.message_id || sendResult.status)) {
          return false;
        }
      } catch {
        return false;
      }

      const messages = await pullMessages(bob, 0, 50);
      return messages.some(message => message.from === aliceAid && messageText(message) === text);
    },
    60_000,
    2_000,
    '等待 Bob 在重连后收到跨域消息',
  );
}

describe('双域 Federation Reconnect 测试', () => {
  const clients: AUNClient[] = [];

  function tracked(tag: string): AUNClient {
    const client = makeClient(tag);
    clients.push(client);
    return client;
  }

  afterEach(async () => {
    await Promise.allSettled(clients.map(client => client.close()));
    clients.length = 0;
  });

  it('远端域 Gateway 重启后自动重连并恢复跨域消息收发', async () => {
    const rid = runId();
    const alice = tracked('alice');
    const bob = tracked('bob');
    const aliceAid = `ts-fed-rc-a-${rid}.aid.com`;
    const bobAid = `ts-fed-rc-b-${rid}.aid.net`;
    const bobStates: string[] = [];

    bob.on('connection.state', (data) => {
      bobStates.push(String(((data as JsonObject).state ?? '')));
    });

    await ensureConnected(alice, aliceAid);
    await ensureConnected(bob, bobAid);

    expect(alice.state).toBe('connected');
    expect(bob.state).toBe('connected');

    touchReconnectMarker();

    await waitFor(
      () => bobStates.includes('disconnected') || bobStates.includes('reconnecting') || bob.state !== 'connected',
      45_000,
      500,
      '等待 Bob 进入断线/重连状态',
    );

    await waitFor(
      () => bob.state === 'connected' && (bobStates.includes('disconnected') || bobStates.includes('reconnecting')),
      90_000,
      500,
      '等待 Bob 重连完成',
    );

    expect(alice.state).toBe('connected');
    expect(bobStates.some(state => state === 'disconnected' || state === 'reconnecting')).toBe(true);

    await waitForFederationDelivery(alice, bob, aliceAid, bobAid, rid);
  }, TEST_TIMEOUT);
});
