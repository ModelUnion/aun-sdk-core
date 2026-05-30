/**
 * message.thought.get 真实链路 E2E 回归测试。
 *
 * 覆盖用户反馈的场景：服务端存在 9 条 mt-* thought，SDK 解密成功后
 * 返回给应用层的 thoughts[] 不能变成空数组。
 */

import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { AUNClient } from '../../src/client.js';
import type { JsonObject } from '../../src/types.js';
import { registerAndLoadIdentity, setGatewayForClient } from '../test-support.js';

process.env.AUN_ENV ??= 'development';

const TEST_TIMEOUT = 90_000;
const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';
const GATEWAY_DISCOVERY_AID = process.env.AUN_TEST_GATEWAY_AID ?? `gateway.${ISSUER}`;

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

function makeClient(): AUNClient {
  const client = new AUNClient({
    aun_path: fs.mkdtempSync(path.join(os.tmpdir(), 'aun-message-thought-')),
  });
  ((client as unknown) as { _configModel: { requireForwardSecrecy: boolean } })._configModel.requireForwardSecrecy = false;
  return client;
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  await setGatewayForClient(client, GATEWAY_DISCOVERY_AID);
  await registerAndLoadIdentity(client, aid);
  await client.connect();
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

describe('message.thought.get 真实链路 E2E', () => {
  const clients: AUNClient[] = [];

  function tracked(): AUNClient {
    const client = makeClient();
    clients.push(client);
    return client;
  }

  afterEach(async () => {
    await Promise.allSettled(clients.map(c => c.close()));
    clients.length = 0;
  });

  it('服务端 9 条 mt-* thought 经 SDK 解密后仍返回 9 条明文 thoughts', async () => {
    const rid = runId();
    const alice = tracked();
    const bob = tracked();
    const aliceAid = `thought-a-${rid}.${ISSUER}`;
    const bobAid = `thought-b-${rid}.${ISSUER}`;
    const context = { type: 'run', id: `thought-run-${rid}` };
    const expectedTexts = Array.from({ length: 9 }, (_, idx) => `thought-${idx}-${rid}`);

    await ensureConnected(alice, aliceAid);
    await ensureConnected(bob, bobAid);

    for (const [idx, text] of expectedTexts.entries()) {
      const put = await alice.call('message.thought.put', {
        to: bobAid,
        context,
        thought_id: `mt-${rid}-${idx}`,
        payload: { type: 'thought', text, index: idx },
        encrypt: true,
      }) as JsonObject;
      expect(Number(put.stored_count ?? 0), `put stored_count idx=${idx}`).toBeGreaterThanOrEqual(idx + 1);
    }

    const raw = await (((bob as unknown) as { _transport: { call: (method: string, params: JsonObject) => Promise<JsonObject> } })._transport.call(
      'message.thought.get',
      { sender_aid: aliceAid, context },
    ));
    const rawThoughts = Array.isArray(raw.thoughts) ? raw.thoughts : [];
    expect(raw.found, `服务端原始返回应 found=true: ${JSON.stringify(raw)}`).toBe(true);
    expect(rawThoughts.length, `服务端原始 thoughts 条数异常: ${JSON.stringify(raw)}`).toBe(expectedTexts.length);

    const result = await bob.call('message.thought.get', {
      sender_aid: aliceAid,
      context,
    }) as JsonObject;
    expect(
      payloadTexts(result),
      `SDK 返回明文 thoughts 不匹配: result=${JSON.stringify(result)} raw_count=${rawThoughts.length}`,
    ).toEqual(expectedTexts);

    const repeat = await bob.call('message.thought.get', {
      sender_aid: aliceAid,
      context,
    }) as JsonObject;
    expect(
      payloadTexts(repeat),
      `重复读取不应被 replay guard 消耗: result=${JSON.stringify(repeat)}`,
    ).toEqual(expectedTexts);
  }, TEST_TIMEOUT);
});
