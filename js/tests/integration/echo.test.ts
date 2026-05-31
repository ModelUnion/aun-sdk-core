/**
 * Echo 链路追踪 E2E 测试 (JS SDK)
 *
 * 验证明文 echo 消息经过 SDK.send → Gateway.route → Message.relay → SDK.receive 的完整 trace 链。
 *
 * 运行：
 *   cd D:\modelunion\kite\aun-sdk-core\js
 *   npm run test:integration -- --reporter=verbose tests/integration/echo.test.ts
 */

import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import * as dns from 'node:dns/promises';
import * as net from 'node:net';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { AUNClient } from '../../src/client.js';
import { registerAndLoadIdentity } from '../test-support.js';

process.env.AUN_ENV ??= 'development';

const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';
const AUN_DATA_ROOT = (process.env.AUN_DATA_ROOT ?? '').trim();

const TEST_AUN_PATH = (process.env.AUN_TEST_AUN_PATH ?? (() => {
  if (AUN_DATA_ROOT) return `${AUN_DATA_ROOT}/single-domain/persistent`;
  return fs.mkdtempSync(path.join(os.tmpdir(), 'aun-echo-'));
})()).trim();

function testAids(): { aliceAid: string; bobAid: string } {
  const runId = rid();
  return {
    aliceAid: process.env.AUN_TEST_ALICE_AID ?? `echo-a-${runId}.${ISSUER}`,
    bobAid: process.env.AUN_TEST_BOB_AID ?? `echo-b-${runId}.${ISSUER}`,
  };
}

function rid(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 8);
}

function makeClient(tag: string): AUNClient {
  const client = new AUNClient();
  (client as any).__testAunPath = TEST_AUN_PATH;
  (client as any).__testDebug = false;
  (client as any).configModel.requireForwardSecrecy = false;
  (client as any)._testSlotId = `echo-${tag}-${rid()}`;
  return client;
}

async function connectClient(client: AUNClient, aid: string): Promise<void> {
  await registerAndLoadIdentity(client, aid);
  const opts: Record<string, unknown> = {
    auto_reconnect: false,
    slot_id: (client as any)._testSlotId ?? `echo-${rid()}`,
  };
  await client.connect(opts);
}

async function safeClose(client: AUNClient): Promise<void> {
  try { await client.close(); } catch {}
}

const clients: AUNClient[] = [];
afterEach(async () => {
  for (const c of clients.splice(0)) await safeClose(c);
});

describe('Echo 链路追踪 E2E (JS)', { timeout: 60_000 }, () => {

  it('P2P 明文 echo 消息包含完整 trace 链', async () => {
    const { aliceAid, bobAid } = testAids();
    const alice = makeClient('alice-echo');
    const bob = makeClient('bob-echo');
    clients.push(alice, bob);

    await connectClient(alice, aliceAid);
    await connectClient(bob, bobAid);

    const received: any[] = [];
    const event = new Promise<void>((resolve) => {
      bob.on('message.received', (msg: any) => {
        received.push(msg);
        resolve();
      });
    });

    const echoText = `echo 测试-${rid()}`;
    await alice.call('message.send', {
      to: bobAid,
      payload: { type: 'text', text: echoText },
      encrypt: false,
    });

    await event;
    const text = received[0]?.payload?.text ?? '';
    console.log('收到:', text.slice(0, 300));

    expect(text).toContain('[AUN-SDK.send]');
    expect(text).toContain('[AUN-Gateway.route]');
    expect(text).toContain('[AUN-Message.relay]');
    expect(text).toContain('[AUN-SDK.receive]');
  });

  it('加密消息不包含 echo trace', async () => {
    const { aliceAid, bobAid } = testAids();
    const alice = makeClient('alice-noecho');
    const bob = makeClient('bob-noecho');
    clients.push(alice, bob);

    await connectClient(alice, aliceAid);
    await connectClient(bob, bobAid);

    const received: any[] = [];
    const event = new Promise<void>((resolve) => {
      bob.on('message.received', (msg: any) => {
        received.push(msg);
        resolve();
      });
    });

    await alice.call('message.send', {
      to: bobAid,
      payload: { type: 'text', text: `echo 加密-${rid()}` },
      encrypt: true,
    });

    await event;
    const text = received[0]?.payload?.text ?? '';
    expect(text).not.toContain('[AUN-SDK.send]');
    expect(text).not.toContain('[AUN-Gateway.route]');
  });

  it('非 echo 明文消息不包含 trace', async () => {
    const { aliceAid, bobAid } = testAids();
    const alice = makeClient('alice-normal');
    const bob = makeClient('bob-normal');
    clients.push(alice, bob);

    await connectClient(alice, aliceAid);
    await connectClient(bob, bobAid);

    const received: any[] = [];
    const event = new Promise<void>((resolve) => {
      bob.on('message.received', (msg: any) => {
        received.push(msg);
        resolve();
      });
    });

    await alice.call('message.send', {
      to: bobAid,
      payload: { type: 'text', text: `普通消息-${rid()}` },
      encrypt: false,
    });

    await event;
    const text = received[0]?.payload?.text ?? '';
    expect(text).not.toContain('[AUN-SDK.send]');
    expect(text).not.toContain('[AUN-Gateway.route]');
  });

  it('Echo trace 顺序正确', async () => {
    const { aliceAid, bobAid } = testAids();
    const alice = makeClient('alice-order');
    const bob = makeClient('bob-order');
    clients.push(alice, bob);

    await connectClient(alice, aliceAid);
    await connectClient(bob, bobAid);

    const received: any[] = [];
    const event = new Promise<void>((resolve) => {
      bob.on('message.received', (msg: any) => {
        received.push(msg);
        resolve();
      });
    });

    await alice.call('message.send', {
      to: bobAid,
      payload: { type: 'text', text: `echo order-${rid()}` },
      encrypt: false,
    });

    await event;
    const text: string = received[0]?.payload?.text ?? '';
    const lines = text.split('\n');

    const markers = ['[AUN-SDK.send]', '[AUN-Gateway.route]', '[AUN-Message.relay]', '[AUN-SDK.receive]'];
    const positions = markers.map(m => lines.findIndex(l => l.includes(m)));

    for (let i = 0; i < positions.length; i++) {
      expect(positions[i], `missing ${markers[i]}`).toBeGreaterThanOrEqual(0);
    }
    for (let i = 1; i < positions.length; i++) {
      expect(positions[i], `${markers[i]} should come after ${markers[i-1]}`).toBeGreaterThan(positions[i-1]);
    }
  });
});
