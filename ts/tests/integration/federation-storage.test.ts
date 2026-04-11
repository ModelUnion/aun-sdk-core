import { afterEach, describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as https from 'node:https';
import * as os from 'node:os';
import * as path from 'node:path';
import { URL } from 'node:url';

import { AUNClient } from '../../src/client.js';
import type { JsonObject } from '../../src/types.js';

const TEST_TIMEOUT = 90_000;

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

function makeClient(tag: string): AUNClient {
  return new AUNClient({
    aun_path: fs.mkdtempSync(path.join(os.tmpdir(), `aun-fed-storage-${tag}-`)),
    verify_ssl: false,
    require_forward_secrecy: false,
    group_e2ee: false,
  });
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  await client.auth.createAid({ aid });
  const auth = await client.auth.authenticate({ aid });
  await client.connect(auth);
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

async function waitFor<T>(
  fn: () => Promise<T>,
  predicate: (value: T) => boolean,
  timeoutMs = 15_000,
  intervalMs = 500,
  label = 'waitFor',
): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let lastValue: T | undefined;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      const value = await fn();
      lastValue = value;
      if (predicate(value)) {
        return value;
      }
    } catch (error) {
      lastError = error;
    }
    await new Promise(resolve => setTimeout(resolve, intervalMs));
  }
  if (lastError) {
    throw new Error(`${label} 超时: ${String(lastError)}`);
  }
  throw new Error(`${label} 超时: ${JSON.stringify(lastValue)}`);
}

async function downloadBytes(urlText: string): Promise<Buffer> {
  const parsed = new URL(urlText);
  const mod = parsed.protocol === 'https:' ? https : http;
  const options = parsed.protocol === 'https:'
    ? ({ rejectUnauthorized: false, timeout: 15_000 } as https.RequestOptions)
    : ({ timeout: 15_000 } as http.RequestOptions);

  return await new Promise<Buffer>((resolve, reject) => {
    const req = mod.get(urlText, options, (res) => {
      const statusCode = res.statusCode ?? 0;
      if (statusCode < 200 || statusCode >= 300) {
        reject(new Error(`HTTP ${statusCode} from ${urlText}`));
        res.resume();
        return;
      }
      const chunks: Buffer[] = [];
      res.on('data', chunk => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error(`timeout fetching ${urlText}`)));
  });
}

function assertNonLoopbackUrl(urlText: string, label: string): void {
  const parsed = new URL(urlText);
  const host = String(parsed.hostname ?? '').trim().toLowerCase();
  expect(host, `${label} 不应为空`).not.toBe('');
  expect(
    ['127.0.0.1', 'localhost', '0.0.0.0', '::1', '::'].includes(host),
    `${label} 不应返回 loopback URL: ${urlText}`,
  ).toBe(false);
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

  it('群资源代理支持跨域下载且拒绝非成员访问', async () => {
    const rid = runId();
    const alice = tracked('group-alice');
    const bob = tracked('group-bob');
    const eve = tracked('group-eve');
    const aliceAid = `ts-sto-grp-a-${rid}.aid.com`;
    const bobAid = `ts-sto-grp-b-${rid}.aid.net`;
    const eveAid = `ts-sto-grp-e-${rid}.aid.net`;

    await ensureConnected(alice, aliceAid);
    await ensureConnected(bob, bobAid);
    await ensureConnected(eve, eveAid);

    const objectKey = `group/private-share-${rid}.txt`;
    const content = Buffer.from(`TS_GROUP_RESOURCE_${rid}`, 'utf-8');
    await rpc(alice, 'storage.put_object', {
      object_key: objectKey,
      content: content.toString('base64'),
      content_type: 'text/plain',
      is_private: true,
    });

    const created = await rpc(alice, 'group.create', { name: `ts-fed-storage-${rid}` });
    const groupId = String(((created.group ?? {}) as JsonObject).group_id ?? '');
    expect(groupId).not.toBe('');

    await rpc(alice, 'group.add_member', { group_id: groupId, aid: bobAid });

    const resourcePath = `files/private-share-${rid}.txt`;
    const direct = await rpc(alice, 'group.resources.direct_add', {
      group_id: groupId,
      resource_path: resourcePath,
      resource_type: 'file',
      title: `private-share-${rid}.txt`,
      storage_ref: {
        owner_aid: aliceAid,
        bucket: 'default',
        object_key: objectKey,
        filename: `private-share-${rid}.txt`,
      },
    });
    expect(String(((direct.resource ?? {}) as JsonObject).resource_path ?? '')).toBe(resourcePath);

    const listed = await waitFor(
      () => rpc(bob, 'group.resources.list', { group_id: groupId }),
      (value) => {
        const items = Array.isArray(value.items) ? value.items : [];
        return items.some(item => String((item as JsonObject).resource_path ?? '') === resourcePath);
      },
      20_000,
      500,
      '等待 Bob 列出群资源',
    );
    const items = Array.isArray(listed.items) ? listed.items : [];
    expect(items.some(item => String((item as JsonObject).resource_path ?? '') === resourcePath)).toBe(true);

    const access = await rpc(bob, 'group.resources.get_access', {
      group_id: groupId,
      resource_path: resourcePath,
    });
    const download = (access.download ?? {}) as JsonObject;
    const downloadUrl = String(download.download_url ?? '');
    expect(downloadUrl).not.toBe('');
    assertNonLoopbackUrl(downloadUrl, 'group.resources.get_access.download_url');

    const body = await downloadBytes(downloadUrl);
    expect(body.equals(content)).toBe(true);

    await expect(rpc(eve, 'group.resources.get_access', {
      group_id: groupId,
      resource_path: resourcePath,
    })).rejects.toThrow();
  }, TEST_TIMEOUT);
});
