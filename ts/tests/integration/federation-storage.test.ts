import { afterEach, describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { AUNClient } from '../../src/client.js';
import type { JsonObject } from '../../src/types.js';
import { createTestClient, registerAndLoadIdentity } from '../test-support.js';

const TEST_TIMEOUT = 90_000;
process.env.AUN_ENV ??= 'development';

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

function makeClient(tag: string): AUNClient {
  return createTestClient({
    aunPath: fs.mkdtempSync(path.join(os.tmpdir(), `aun-fed-storage-${tag}-`)),
    requireForwardSecrecy: false,
  });
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  await registerAndLoadIdentity(client, aid);
  await client.connect();
}

async function rpc(client: AUNClient, method: string, params: JsonObject): Promise<JsonObject> {
  const result = await client.call(method, params) as JsonObject;
  const maybeError = result.error;
  if (maybeError && typeof maybeError === 'object' && !Array.isArray(maybeError)) {
    const message = String(((maybeError as JsonObject).message ?? maybeError) || maybeError);
    throw new Error(`${method} 失败: ${message}`);
  }
  return result;
}

describe('双域 Federation Storage 测试', () => {
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

  it('公开对象支持跨域 inline 读取', async () => {
    const rid = runId();
    const alice = tracked('public-alice');
    const bob = tracked('public-bob');
    const aliceAid = `ts-sto-pub-a-${rid}.aid.com`;
    const bobAid = `ts-sto-pub-b-${rid}.aid.net`;

    await ensureConnected(alice, aliceAid);
    await ensureConnected(bob, bobAid);

    const objectKey = `shared/public-${rid}.txt`;
    const content = Buffer.from(`TS_PUBLIC_CROSS_DOMAIN_${rid}`, 'utf-8');
    const putResult = await rpc(alice, 'storage.put_object', {
      object_key: objectKey,
      content: content.toString('base64'),
      content_type: 'text/plain',
      is_private: false,
    });
    expect(String(putResult.object_key ?? '')).toBe(objectKey);

    const head = await rpc(bob, 'storage.head_object', {
      owner_aid: aliceAid,
      object_key: objectKey,
    });
    expect(Number(head.size_bytes ?? 0)).toBe(content.length);
    expect(head.is_private).toBe(false);

    const objectResult = await rpc(bob, 'storage.get_object', {
      owner_aid: aliceAid,
      object_key: objectKey,
    });
    const actual = Buffer.from(String(objectResult.content ?? ''), 'base64');
    expect(actual.equals(content)).toBe(true);
  }, TEST_TIMEOUT);

  it('私有对象跨域直读会被拒绝', async () => {
    const rid = runId();
    const alice = tracked('private-alice');
    const bob = tracked('private-bob');
    const aliceAid = `ts-sto-pri-a-${rid}.aid.com`;
    const bobAid = `ts-sto-pri-b-${rid}.aid.net`;

    await ensureConnected(alice, aliceAid);
    await ensureConnected(bob, bobAid);

    const objectKey = `private/hidden-${rid}.txt`;
    const content = Buffer.from(`TS_PRIVATE_ONLY_${rid}`, 'utf-8');
    await rpc(alice, 'storage.put_object', {
      object_key: objectKey,
      content: content.toString('base64'),
      content_type: 'text/plain',
      is_private: true,
    });

    await expect(rpc(bob, 'storage.head_object', {
      owner_aid: aliceAid,
      object_key: objectKey,
    })).rejects.toThrow();

    await expect(rpc(bob, 'storage.get_object', {
      owner_aid: aliceAid,
      object_key: objectKey,
    })).rejects.toThrow();
  }, TEST_TIMEOUT);
});
