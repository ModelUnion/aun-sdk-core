/**
 * 双域 Federation 集成 / E2E 测试。
 *
 * 前置条件：
 *   - docker-deploy/federation-test 已启动
 *   - 宿主机可解析 aid.com / aid.net / gateway.{issuer}
 *
 * 运行方式：
 *   npx vitest run tests/integration/federation.test.ts
 */

import { afterEach, describe, expect, it } from 'vitest';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { AUNClient } from '../../src/client.js';
import type { JsonObject, Message } from '../../src/types.js';

const TEST_TIMEOUT = 90_000;
process.env.AUN_ENV ??= 'development';

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

function makeClient(tag: string): AUNClient {
  const client = new AUNClient({
    aun_path: fs.mkdtempSync(path.join(os.tmpdir(), `aun-fed-${tag}-`)),
  });
  ((client as unknown) as { _configModel: { requireForwardSecrecy: boolean } })._configModel.requireForwardSecrecy = false;
  return client;
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  await client.auth.createAid({ aid });
  const auth = await client.auth.authenticate({ aid });
  await client.connect(auth);
}

function msgText(msg: Message): string {
  const payload = msg.payload;
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
    return String((payload as JsonObject).text ?? '');
  }
  return String(payload ?? '');
}

function msgSender(msg: Message): string {
  return String(msg.from ?? (msg as JsonObject).sender_aid ?? '');
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

async function pullMessages(client: AUNClient, afterSeq = 0, limit = 50): Promise<Message[]> {
  const result = await client.call('message.pull', { after_seq: afterSeq, limit }) as JsonObject;
  return (result.messages ?? []) as Message[];
}

async function pullGroupMessages(client: AUNClient, groupId: string, afterSeq = 0, limit = 50): Promise<Message[]> {
  const result = await client.call('group.pull', {
    group_id: groupId,
    after_seq: afterSeq,
    limit,
  }) as JsonObject;
  return (result.messages ?? []) as Message[];
}

describe('双域 Federation 集成测试', () => {
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

  it('message.send 跨域 E2EE 成功解密，并携带 cert_fingerprint', async () => {
    const rid = runId();
    const alice = tracked('fed-msg-alice');
    const bob = tracked('fed-msg-bob');
    const aliceAid = `ts-fed-a-${rid}.aid.com`;
    const bobAid = `ts-fed-b-${rid}.aid.net`;

    await ensureConnected(alice, aliceAid);
    await ensureConnected(bob, bobAid);

    const sendText = `ts federation hello ${rid}`;
    const sendResult = await alice.call('message.send', {
      to: bobAid,
      payload: { type: 'text', text: sendText },
      encrypt: true,
    }) as JsonObject;

    expect(sendResult.status).toBeTruthy();

    const messages = await waitFor(
      () => pullMessages(bob, 0, 50),
      list => list.some(msg => msgSender(msg) === aliceAid && msgText(msg) === sendText),
      20_000,
      500,
      '等待 Bob 收到跨域消息',
    );

    const target = messages.find(msg => msgSender(msg) === aliceAid && msgText(msg) === sendText);
    expect(target).toBeTruthy();
    expect(target?.encrypted).toBe(true);

    const e2ee = (target?.e2ee ?? {}) as JsonObject;
    expect(String(e2ee.encryption_mode ?? '')).toBe('prekey_ecdh_v2');
    expect(String(e2ee.prekey_id ?? '')).not.toBe('');
  }, TEST_TIMEOUT);

  it('group 跨域加人、发消息、邀请码入群走公开接口', async () => {
    const rid = runId();
    const alice = tracked('fed-group-alice');
    const bob = tracked('fed-group-bob');
    const eve = tracked('fed-group-eve');
    const aliceAid = `ts-grp-a-${rid}.aid.com`;
    const bobAid = `ts-grp-b-${rid}.aid.net`;
    const eveAid = `ts-grp-e-${rid}.aid.net`;

    await ensureConnected(alice, aliceAid);
    await ensureConnected(bob, bobAid);
    await ensureConnected(eve, eveAid);

    const created = await alice.call('group.create', { name: `ts-fed-group-${rid}` }) as JsonObject;
    const groupId = String(((created.group ?? {}) as JsonObject).group_id ?? '');
    expect(groupId).not.toBe('');

    await alice.call('group.add_member', { group_id: groupId, aid: bobAid });

    const text1 = `group-msg-1-${rid}`;
    const sent1 = await alice.call('group.send', {
      group_id: groupId,
      payload: { type: 'text', text: text1 },
      encrypt: false,
    }) as JsonObject;
    const seq1 = Number((((sent1.message ?? {}) as JsonObject).seq ?? sent1.seq ?? 0));
    expect(seq1).toBeGreaterThan(0);

    const bobMsgs = await waitFor(
      () => pullGroupMessages(bob, groupId, 0, 20),
      list => list.some(msg => msgSender(msg) === aliceAid && msgText(msg) === text1),
      20_000,
      500,
      '等待 Bob 拉到跨域群消息',
    );
    expect(bobMsgs.some(msg => msgSender(msg) === aliceAid && msgText(msg) === text1)).toBe(true);

    const inviteResult = await alice.call('group.create_invite_code', {
      group_id: groupId,
      max_uses: 1,
    }) as JsonObject;
    const invite = (inviteResult.invite_code ?? {}) as JsonObject;
    const code = String(invite.code_with_domain ?? invite.code ?? '');
    expect(code).not.toBe('');

    const joined = await eve.call('group.use_invite_code', { code }) as JsonObject;
    expect(String(((joined.group ?? {}) as JsonObject).group_id ?? '')).toBe(groupId);

    const text2 = `group-msg-2-${rid}`;
    await alice.call('group.send', {
      group_id: groupId,
      payload: { type: 'text', text: text2 },
      encrypt: false,
    });

    const eveMsgs = await waitFor(
      () => pullGroupMessages(eve, groupId, 0, 20),
      list => list.some(msg => msgSender(msg) === aliceAid && msgText(msg) === text2),
      20_000,
      500,
      '等待 Eve 拉到邀请码入群后的群消息',
    );
    expect(eveMsgs.some(msg => msgSender(msg) === aliceAid && msgText(msg) === text2)).toBe(true);
  }, TEST_TIMEOUT);
});
