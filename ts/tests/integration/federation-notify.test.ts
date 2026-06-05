/**
 * Notify 跨域 Federation 测试。
 *
 * 运行：
 *   cd /workspace/ts && npx vitest run tests/integration/federation-notify.test.ts
 */

import { afterEach, describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { AUNClient } from '../../src/client.js';
import type { JsonObject } from '../../src/types.js';
import { createTestClient, registerAndLoadIdentity } from '../test-support.js';

process.env.AUN_ENV ??= 'development';

const TEST_TIMEOUT = 90_000;
const ISSUER_A = process.env.AUN_TEST_ISSUER_A ?? 'aid.com';
const ISSUER_B = process.env.AUN_TEST_ISSUER_B ?? 'aid.net';

function rid(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 10);
}

function makeClient(tag: string): AUNClient {
  return createTestClient({
    aunPath: fs.mkdtempSync(path.join(os.tmpdir(), `aun-ts-fed-notify-${tag}-`)),
    requireForwardSecrecy: false,
  });
}

async function connectClient(client: AUNClient, aid: string): Promise<void> {
  await registerAndLoadIdentity(client, aid);
  await client.connect({ auto_reconnect: false });
  await new Promise(resolve => setTimeout(resolve, 500));
}

function waitForMaybeAppEvent(
  client: AUNClient,
  event: string,
  token: string,
  timeoutMs = 12_000,
): Promise<JsonObject | null> {
  return new Promise(resolve => {
    let done = false;
    const sub = client.on(event, (payload: unknown) => {
      const data = payload as JsonObject;
      if (!data || data.token !== token || done) return;
      done = true;
      clearTimeout(timer);
      sub.unsubscribe();
      resolve(data);
    });
    const timer = setTimeout(() => {
      if (done) return;
      done = true;
      sub.unsubscribe();
      resolve(null);
    }, timeoutMs);
  });
}

describe('Notify 跨域 Federation 测试', () => {
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

  it('AID notify 应能从 aid.com 在线投递到 aid.net', async () => {
    const r = rid();
    const aliceAid = `ts-notify-xa-${r}.${ISSUER_A}`;
    const bobAid = `ts-notify-xb-${r}.${ISSUER_B}`;
    const token = `cross-${r}`;
    const alice = tracked('alice');
    const bob = tracked('bob');

    await connectClient(alice, aliceAid);
    await connectClient(bob, bobAid);

    const received = waitForMaybeAppEvent(bob, 'app.cross_domain_ping', token);
    await alice.notify(
      'event/app.cross_domain_ping',
      { token, from: aliceAid },
      { to: bobAid, ttl_ms: 10_000 },
    );

    const payload = await received;
    expect(payload).not.toBeNull();
    expect(payload?.token).toBe(token);
    expect((payload?._notify as JsonObject)?.from_aid).toBe(aliceAid);
  }, TEST_TIMEOUT);
});
