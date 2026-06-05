/**
 * Notify 单域集成测试 (JS SDK)。
 *
 * 运行：
 *   cd /workspace/js && npm run test:integration -- tests/integration/notify.test.ts
 */

import { afterEach, describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { AUNClient } from '../../src/client.js';
import type { JsonObject } from '../../src/types.js';
import { registerAndLoadIdentity } from '../test-support.js';

process.env.AUN_ENV ??= 'development';

const TEST_TIMEOUT = 60_000;
const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';

function rid(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 10);
}

function makePath(tag: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), `aun-js-notify-${tag}-`));
}

function makeClient(tag: string, aunPath?: string): AUNClient {
  const client = new AUNClient();
  (client as any).__testAunPath = aunPath ?? makePath(tag);
  (client as any).__testDebug = false;
  (client as any).configModel.requireForwardSecrecy = false;
  return client;
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

function waitForMaybeAppEvent(
  client: AUNClient,
  event: string,
  token: string,
  timeoutMs: number,
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

function clientDeviceId(client: AUNClient): string {
  const raw = client as any;
  return String(raw._deviceId ?? raw.currentAid?.deviceId ?? raw.currentAid?.device_id ?? '');
}

describe('Notify 单域集成测试 (JS)', () => {
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
    const aliceAid = `js-notify-a-${r}.${ISSUER}`;
    const bobAid = `js-notify-b-${r}.${ISSUER}`;
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
  }, TEST_TIMEOUT);

  it('device_id + slot_id 应只投递到目标 slot', async () => {
    const r = rid();
    const aliceAid = `js-notify-slot-a-${r}.${ISSUER}`;
    const bobAid = `js-notify-slot-b-${r}.${ISSUER}`;
    const token = `slot-${r}`;
    const bobPath = makePath('bob-shared');
    const targetSlot = `target-${r}`;
    const otherSlot = `other-${r}`;
    const alice = tracked('slot-alice');
    const bobTarget = tracked('slot-target', bobPath);
    const bobOther = tracked('slot-other', bobPath);

    await connectClient(alice, aliceAid, `alice-${r}`);
    await connectClient(bobTarget, bobAid, targetSlot);
    await connectClient(bobOther, bobAid, otherSlot);

    const deviceId = clientDeviceId(bobTarget);
    expect(deviceId).not.toBe('');

    const targetReceived = waitForMaybeAppEvent(bobTarget, 'app.slot_probe', token, 8_000);
    const otherReceived = waitForMaybeAppEvent(bobOther, 'app.slot_probe', token, 1_500);
    await alice.notify(
      'event/app.slot_probe',
      { token, slot: targetSlot },
      { to: bobAid, device_id: deviceId, slot_id: targetSlot, ttl_ms: 8000 },
    );

    await expect(targetReceived).resolves.toMatchObject({ token, slot: targetSlot });
    await expect(otherReceived).resolves.toBeNull();
  }, TEST_TIMEOUT);
});
