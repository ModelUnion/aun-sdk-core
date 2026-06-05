/**
 * Notify 端到端边界测试。
 *
 * 运行：
 *   cd /workspace/ts && npx vitest run tests/e2e/notify.test.ts
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

function makePath(tag: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), `aun-ts-notify-e2e-${tag}-`));
}

function makeClient(tag: string, aunPath?: string): AUNClient {
  return createTestClient({
    aunPath: aunPath ?? makePath(tag),
    requireForwardSecrecy: false,
  });
}

async function connectClient(client: AUNClient, aid: string, slotId?: string): Promise<void> {
  await registerAndLoadIdentity(client, aid, slotId);
  await client.connect({ auto_reconnect: false });
  await new Promise(resolve => setTimeout(resolve, 300));
}

function waitForMaybeAppEvent(
  client: AUNClient,
  event: string,
  token: string,
  timeoutMs: number,
): Promise<JsonObject | null> {
  return new Promise((resolve) => {
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

function subscribeAppEvent(client: AUNClient, event: string, token: string): {
  messages: JsonObject[];
  wait: (timeoutMs: number) => Promise<JsonObject | null>;
  unsubscribe: () => void;
} {
  const messages: JsonObject[] = [];
  let resolver: ((value: JsonObject | null) => void) | null = null;
  const sub = client.on(event, (payload: unknown) => {
    const data = payload as JsonObject;
    if (!data || data.token !== token) return;
    messages.push(data);
    if (resolver) {
      const resolve = resolver;
      resolver = null;
      resolve(data);
    }
  });
  return {
    messages,
    wait: (timeoutMs: number) => new Promise(resolve => {
      if (messages.length > 0) {
        resolve(messages[messages.length - 1]);
        return;
      }
      resolver = resolve;
      setTimeout(() => {
        if (!resolver) return;
        resolver = null;
        resolve(null);
      }, timeoutMs);
    }),
    unsubscribe: () => sub.unsubscribe(),
  };
}

function clientDeviceId(client: AUNClient): string {
  const raw = client as any;
  return String(raw._deviceId ?? raw.currentAid?.deviceId ?? raw.currentAid?.device_id ?? '');
}

describe('Notify 端到端边界测试', () => {
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

  it('device_id + slot_id 应只投递到目标 slot', async () => {
    const r = rid();
    const aliceAid = `ts-notify-slot-a-${r}.${ISSUER}`;
    const bobAid = `ts-notify-slot-b-${r}.${ISSUER}`;
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

  it('离线 notify 不应存储，目标重连后不补发', async () => {
    const r = rid();
    const aliceAid = `ts-notify-off-a-${r}.${ISSUER}`;
    const bobAid = `ts-notify-off-b-${r}.${ISSUER}`;
    const token = `offline-${r}`;
    const bobPath = makePath('offline-bob');
    const alice = tracked('offline-alice');
    const bobSetup = tracked('offline-bob-setup', bobPath);
    const bobLate = tracked('offline-bob-late', bobPath);

    await connectClient(alice, aliceAid, `alice-${r}`);
    await registerAndLoadIdentity(bobSetup, bobAid, `late-${r}`);
    await bobSetup.close();

    const collector = subscribeAppEvent(bobLate, 'app.offline_probe', token);
    await alice.notify(
      'event/app.offline_probe',
      { token, phase: 'while-offline' },
      { to: bobAid, ttl_ms: 3000 },
    );
    await connectClient(bobLate, bobAid, `late-${r}`);

    try {
      await expect(collector.wait(3_000)).resolves.toBeNull();
      expect(collector.messages).toHaveLength(0);
    } finally {
      collector.unsubscribe();
    }
  }, TEST_TIMEOUT);
});
