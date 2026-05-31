/**
 * 双域 V2 thought.put / thought.get 集成测试。
 *
 * 验证跨域 V2 加密 thought 的完整链路：
 * - 跨域 P2P thought.put（envelope 走 V2 e2ee.p2p_encrypted）
 * - 跨域 P2P thought.get 单设备解密
 * - 跨域 Group thought.put / thought.get（envelope 走 V2 e2ee.group_encrypted）
 *
 * 前置条件：
 *   - docker-deploy/federation-test 已启动
 *   - 宿主机可解析 aid.com / aid.net / gateway.{issuer}
 *
 * 运行方式（容器内）：
 *   npx vitest run tests/integration/federation-v2-thought.test.ts
 */

import { afterEach, describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { AUNClient } from '../../src/client.js';
import type { JsonObject } from '../../src/types.js';
import { createTestClient, registerAndLoadIdentity } from '../test-support.js';

const TEST_TIMEOUT = 120_000;
process.env.AUN_ENV ??= 'development';

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

function makeClient(tag: string): AUNClient {
  return createTestClient({
    aunPath: fs.mkdtempSync(path.join(os.tmpdir(), `aun-fed-v2t-${tag}-`)),
    requireForwardSecrecy: false,
  });
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  await registerAndLoadIdentity(client, aid);
  await client.connect();
  // V2 session 必须显式初始化
  await (client as any)._initV2Session();
}

function payloadTexts(result: JsonObject): string[] {
  const thoughts = Array.isArray(result.thoughts) ? result.thoughts : [];
  const texts: string[] = [];
  for (const item of thoughts) {
    const thought = item as JsonObject;
    const payload = thought.payload as JsonObject | undefined;
    const text = typeof payload?.text === 'string' ? payload.text : '';
    if (text) texts.push(text);
  }
  return texts;
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
      if (predicate(value)) return value;
    } catch (error) {
      lastError = error;
    }
    await new Promise(resolve => setTimeout(resolve, intervalMs));
  }
  if (lastError) throw new Error(`${label} 超时: ${String(lastError)}`);
  throw new Error(`${label} 超时: ${JSON.stringify(lastValue)}`);
}

describe('双域 V2 thought 集成测试', () => {
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

  it('跨域 P2P thought.put / thought.get 走 V2 envelope 并解密', async () => {
    const rid = runId();
    const alice = tracked('p2p-alice');
    const bob = tracked('p2p-bob');
    const aliceAid = `ts-fedv2t-a-${rid}.aid.com`;
    const bobAid = `ts-fedv2t-b-${rid}.aid.net`;

    await ensureConnected(alice, aliceAid);
    await ensureConnected(bob, bobAid);

    expect((alice as unknown as { _v2Session: unknown })._v2Session).not.toBeNull();
    expect((bob as unknown as { _v2Session: unknown })._v2Session).not.toBeNull();

    const text = `fed-v2t-p2p ${rid} ${Date.now()}`;
    const ctx = { type: 'fed-v2t-run', id: `fed-v2t-p2p-${rid}` };

    // Alice 写：走 V2 加密路径
    const put = await alice.call('message.thought.put', {
      to: bobAid,
      context: ctx,
      thought_id: `mt-fed-v2t-${rid}`,
      payload: { type: 'thought', text },
    }) as JsonObject;
    expect(Number(put.stored_count ?? 0), `unexpected put result: ${JSON.stringify(put)}`).toBeGreaterThanOrEqual(1);

    // Bob 直读 transport：验证 envelope.type 是 V2 P2P 加密格式
    const raw = await ((bob as unknown) as { _transport: { call: (m: string, p: JsonObject) => Promise<JsonObject> } })._transport.call(
      'message.thought.get',
      { sender_aid: aliceAid, context: ctx },
    );
    const items = Array.isArray(raw.thoughts) ? raw.thoughts : [];
    expect(items.length, `server raw thoughts empty: ${JSON.stringify(raw)}`).toBeGreaterThanOrEqual(1);
    const firstPayload = (items[0] as JsonObject).payload as JsonObject || {};
    expect(firstPayload.type, `V2 P2P thought payload.type 必须为 e2ee.p2p_encrypted，实际=${String(firstPayload.type)}`).toBe('e2ee.p2p_encrypted');
    const recipients = firstPayload.recipients;
    expect(Array.isArray(recipients) && (recipients as unknown[]).length > 0,
      `V2 P2P thought envelope 必须包含 recipients[]`).toBe(true);

    // Bob 走 SDK 路径解密
    const got = await waitFor(
      () => bob.call('message.thought.get', { sender_aid: aliceAid, context: ctx }) as Promise<JsonObject>,
      r => payloadTexts(r).includes(text),
      20_000,
      500,
      '等待 Bob 解密跨域 V2 P2P thought',
    );
    expect(payloadTexts(got)).toContain(text);
  }, TEST_TIMEOUT);

  it('跨域 Group thought.put / thought.get 走 V2 envelope 并解密', async () => {
    const rid = runId();
    const alice = tracked('grp-alice');
    const bob = tracked('grp-bob');
    const aliceAid = `ts-fedv2gt-a-${rid}.aid.com`;
    const bobAid = `ts-fedv2gt-b-${rid}.aid.net`;

    await ensureConnected(alice, aliceAid);
    await ensureConnected(bob, bobAid);

    // 创建群（V2 capability 已在 connect 时上报，群默认走 V2）
    const created = await alice.call('group.create', { name: `ts-fedv2t-grp-${rid}` }) as JsonObject;
    const groupId = String(((created.group ?? {}) as JsonObject).group_id ?? '');
    expect(groupId).not.toBe('');

    await alice.call('group.add_member', { group_id: groupId, aid: bobAid });
    // 等待 Bob 接收到群同步事件，使其 V2 group bootstrap 就绪
    await new Promise(resolve => setTimeout(resolve, 2000));

    const text = `fed-v2t-grp ${rid} ${Date.now()}`;
    const ctx = { type: 'fed-v2t-grp', id: `fed-v2t-grp-${rid}` };

    const put = await alice.call('group.thought.put', {
      group_id: groupId,
      context: ctx,
      payload: { type: 'thought', text },
    }) as JsonObject;
    expect(typeof put === 'object' && put !== null, `group.thought.put 失败: ${JSON.stringify(put)}`).toBe(true);

    // 直读服务端：envelope 必须是 V2 group 加密格式
    const raw = await ((bob as unknown) as { _transport: { call: (m: string, p: JsonObject) => Promise<JsonObject> } })._transport.call(
      'group.thought.get',
      { group_id: groupId, sender_aid: aliceAid, context: ctx },
    );
    const items = Array.isArray(raw.thoughts) ? raw.thoughts : [];
    expect(items.length, `server raw group thoughts empty: ${JSON.stringify(raw)}`).toBeGreaterThanOrEqual(1);
    const firstPayload = (items[0] as JsonObject).payload as JsonObject || {};
    expect(firstPayload.type, `V2 group thought payload.type 必须为 e2ee.group_encrypted，实际=${String(firstPayload.type)}`).toBe('e2ee.group_encrypted');
    const recipients = firstPayload.recipients;
    expect(Array.isArray(recipients) && (recipients as unknown[]).length > 0,
      `V2 group thought envelope 必须含 recipients[]`).toBe(true);

    // Bob 走 SDK 路径解密
    const got = await waitFor(
      () => bob.call('group.thought.get', {
        group_id: groupId, sender_aid: aliceAid, context: ctx,
      }) as Promise<JsonObject>,
      r => payloadTexts(r).includes(text),
      20_000,
      500,
      '等待 Bob 解密跨域 V2 group thought',
    );
    expect(payloadTexts(got)).toContain(text);
  }, TEST_TIMEOUT);
});
