/**
 * Notify 单域集成测试。
 *
 * 运行：
 *   cd /workspace/ts && npx vitest run tests/integration/notify.test.ts
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

const TEST_TIMEOUT = 60_000;
const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';

function rid(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 10);
}

function makeClient(tag: string, aunPath?: string): AUNClient {
  return createTestClient({
    aunPath: aunPath ?? fs.mkdtempSync(path.join(os.tmpdir(), `aun-ts-notify-${tag}-`)),
    requireForwardSecrecy: false,
  });
}

async function connectClient(client: AUNClient, aid: string, slotId?: string): Promise<void> {
  await registerAndLoadIdentity(client, aid, slotId);
  await client.connect({ auto_reconnect: false });
  await new Promise(resolve => setTimeout(resolve, 300));
}

function waitForAppEvent(
  client: AUNClient,
  event: string,
  token: string,
  timeoutMs = 8_000,
): Promise<JsonObject> {
  return new Promise((resolve, reject) => {
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
      reject(new Error(`等待 ${event} notify 超时: token=${token}`));
    }, timeoutMs);
  });
}

describe('Notify 单域集成测试', () => {
  const clients: AUNClient[] = [];

  function tracked(tag: string, aunPath?: string): AUNClient {
    const client = makeClient(tag, aunPath);
    clients.push(client);
    return client;
  }

  afterEach(async () => {
    await Promise.allSettled(clients.map(client => client.close()));
    clients.length = 0;
  });

  it('AID 在线 notify 应实时投递 app.* 事件', async () => {
    const r = rid();
    const aliceAid = `ts-notify-a-${r}.${ISSUER}`;
    const bobAid = `ts-notify-b-${r}.${ISSUER}`;
    const token = `aid-${r}`;
    const alice = tracked('aid-alice');
    const bob = tracked('aid-bob');

    await connectClient(alice, aliceAid, `alice-${r}`);
    await connectClient(bob, bobAid, `bob-${r}`);

    const received = waitForAppEvent(bob, 'app.typing', token);
    await alice.notify(
      'event/app.typing',
      { token, thread_id: `thread-${r}` },
      { to: bobAid, ttl_ms: 5000 },
    );

    const payload = await received;
    expect(payload.thread_id).toBe(`thread-${r}`);
    expect((payload._notify as JsonObject)?.from_aid).toBe(aliceAid);
    expect((payload._notify as JsonObject)?.ttl_ms).toBe(5000);
  }, TEST_TIMEOUT);

  it('group notify 应投递给在线群成员', async () => {
    const r = rid();
    const aliceAid = `ts-notify-ga-${r}.${ISSUER}`;
    const bobAid = `ts-notify-gb-${r}.${ISSUER}`;
    const token = `group-${r}`;
    const alice = tracked('group-alice');
    const bob = tracked('group-bob');

    await connectClient(alice, aliceAid, `ga-${r}`);
    await connectClient(bob, bobAid, `gb-${r}`);

    const created = await alice.call('group.create', { name: `ts-notify-group-${r}` }) as JsonObject;
    const groupId = String(((created.group ?? {}) as JsonObject).group_id ?? '');
    expect(groupId).not.toBe('');
    await alice.call('group.add_member', { group_id: groupId, aid: bobAid });
    await new Promise(resolve => setTimeout(resolve, 1000));

    const received = waitForAppEvent(bob, 'app.presence', token);
    await alice.notify('event/app.presence', { token, state: 'active' }, { group_id: groupId });

    const payload = await received;
    expect(payload.state).toBe('active');
    expect(payload.group_id).toBe(groupId);
    expect((payload._notify as JsonObject)?.from_aid).toBe(aliceAid);
  }, TEST_TIMEOUT);
});
