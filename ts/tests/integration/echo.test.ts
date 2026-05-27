/**
 * Echo 链路追踪 E2E 测试
 *
 * 验证明文 echo 消息经过 SDK.send → Gateway.route → Message.relay → SDK.receive 的完整 trace 链。
 *
 * 运行环境（容器内）：
 *   MSYS_NO_PATHCONV=1 docker exec kite-ts-tester bash -lc \
 *     "cd /workspace/ts && npx vitest run tests/integration/echo.test.ts"
 */

import { describe, it, expect, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { AUNClient } from '../../src/client.js';

process.env.AUN_ENV ??= 'development';

const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';
const GATEWAY_DISCOVERY_AID = process.env.AUN_TEST_GATEWAY_AID ?? `gateway.${ISSUER}`;
const AUN_DATA_ROOT = (process.env.AUN_DATA_ROOT ?? '').trim();

const TEST_AUN_PATH = (process.env.AUN_TEST_AUN_PATH ?? (() => {
  if (AUN_DATA_ROOT) return `${AUN_DATA_ROOT}/single-domain/persistent`;
  return './.aun_test';
})()).trim();

function rid(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 8);
}

function makeAunPath(tag: string): string {
  const base = AUN_DATA_ROOT
    ? path.join(AUN_DATA_ROOT, 'single-domain', 'echo-tmp')
    : os.tmpdir();
  const root = path.join(base, `ts_echo_${tag}_${rid()}`);
  fs.mkdirSync(root, { recursive: true });
  return root;
}

function makeClient(tag: string): AUNClient {
  const aunPath = makeAunPath(tag);
  const client = new AUNClient({ aun_path: aunPath }, false);
  (client as any)._configModel.requireForwardSecrecy = false;
  (client as any)._testSlotId = `echo-${tag}-${rid()}`;
  return client;
}

async function resolveGatewayInto(client: AUNClient): Promise<void> {
  const gateway = await client.auth._resolveGateway(GATEWAY_DISCOVERY_AID);
  (client as any)._gatewayUrl = gateway;
}

async function connectClient(client: AUNClient, aid: string): Promise<void> {
  await resolveGatewayInto(client);
  await client.auth.registerAid({ aid });
  const auth = await client.auth.authenticate({ aid });
  const opts: Record<string, unknown> = {
    ...auth,
    auto_reconnect: false,
    slot_id: (client as any)._testSlotId ?? `echo-${rid()}`,
  };
  await client.connect(opts);
}

async function safeClose(client: AUNClient): Promise<void> {
  try { await client.close(); } catch {}
}

const clients: AUNClient[] = [];
afterAll(async () => {
  for (const c of clients) await safeClose(c);
});

describe('Echo 链路追踪 E2E', { timeout: 60_000 }, () => {

  it('P2P 明文 echo 消息包含完整 trace 链', async () => {
    const r = rid();
    const aliceAid = `echo-alice-${r}.${ISSUER}`;
    const bobAid = `echo-bob-${r}.${ISSUER}`;
    const alice = makeClient('alice');
    const bob = makeClient('bob');
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

    const echoText = `echo 测试-${r}`;
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
    const r = rid();
    const aliceAid = `echo-enc-a-${r}.${ISSUER}`;
    const bobAid = `echo-enc-b-${r}.${ISSUER}`;
    const alice = makeClient('enc-alice');
    const bob = makeClient('enc-bob');
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
      payload: { type: 'text', text: `echo 加密-${r}` },
      encrypt: true,
    });

    await event;
    const text = received[0]?.payload?.text ?? '';
    expect(text).not.toContain('[AUN-SDK.send]');
    expect(text).not.toContain('[AUN-Gateway.route]');
  });

  it('非 echo 明文消息不包含 trace', async () => {
    const r = rid();
    const aliceAid = `echo-norm-a-${r}.${ISSUER}`;
    const bobAid = `echo-norm-b-${r}.${ISSUER}`;
    const alice = makeClient('norm-alice');
    const bob = makeClient('norm-bob');
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
      payload: { type: 'text', text: `普通消息-${r}` },
      encrypt: false,
    });

    await event;
    const text = received[0]?.payload?.text ?? '';
    expect(text).not.toContain('[AUN-SDK.send]');
    expect(text).not.toContain('[AUN-Gateway.route]');
  });

  it('Echo trace 顺序正确: send → gateway → message → receive', async () => {
    const r = rid();
    const aliceAid = `echo-ord-a-${r}.${ISSUER}`;
    const bobAid = `echo-ord-b-${r}.${ISSUER}`;
    const alice = makeClient('ord-alice');
    const bob = makeClient('ord-bob');
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
      payload: { type: 'text', text: `echo order-${r}` },
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

  it('Echo trace 中 conn_uptime 为非负整数', async () => {
    const r = rid();
    const aliceAid = `echo-up-a-${r}.${ISSUER}`;
    const bobAid = `echo-up-b-${r}.${ISSUER}`;
    const alice = makeClient('up-alice');
    const bob = makeClient('up-bob');
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
      payload: { type: 'text', text: `echo uptime-${r}` },
      encrypt: false,
    });

    await event;
    const text: string = received[0]?.payload?.text ?? '';
    const uptimes = [...text.matchAll(/conn_uptime=(\d+)s/g)].map(m => parseInt(m[1]));
    expect(uptimes.length).toBeGreaterThanOrEqual(2);
    for (const u of uptimes) {
      expect(u).toBeGreaterThanOrEqual(0);
    }
  });
});
