/**
 * 群消息 gap 检测与自动补洞集成测试 — 对应 P1-7 修复
 *
 * 验证群消息 push 带 payload 时发现 seq gap 也必须补洞，
 * 最终业务层收到完整有序群消息序列。
 */

import { afterEach, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { AUNClient } from '../../src/index.js';

process.env.AUN_ENV ??= 'development';

const AUN_DATA_ROOT = process.env.AUN_DATA_ROOT ?? '';
const TEST_AUN_PATH = process.env.AUN_TEST_AUN_PATH
  ?? (AUN_DATA_ROOT ? `${AUN_DATA_ROOT}/single-domain/persistent` : '');
const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';
const ALICE_AID = process.env.AUN_TEST_ALICE_AID ?? `alice.${ISSUER}`;
const BOB_AID = process.env.AUN_TEST_BOB_AID ?? `bob.${ISSUER}`;
const CAROL_AID = process.env.AUN_TEST_CAROL_AID ?? `carol.${ISSUER}`;

function makeClient(): AUNClient {
  const aunPath = TEST_AUN_PATH || fs.mkdtempSync(path.join(os.tmpdir(), 'aun-ggap-'));
  const client = new AUNClient({ aun_path: aunPath });
  ((client as unknown) as { _configModel: { requireForwardSecrecy: boolean } })._configModel.requireForwardSecrecy = false;
  return client;
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  await client.auth.createAid({ aid });
  const auth = await client.auth.authenticate({ aid });
  await client.connect(auth);
}

describe('Group Message Gap Fill', { timeout: 45000 }, () => {
  let alice: AUNClient;
  let bob: AUNClient;
  let carol: AUNClient;

  afterEach(async () => {
    await alice?.close();
    await bob?.close();
    await carol?.close();
  });

  it('群消息应自动补洞并按序投递', async () => {
    alice = makeClient();
    bob = makeClient();
    carol = makeClient();
    await ensureConnected(alice, ALICE_AID);
    await ensureConnected(bob, BOB_AID);
    await ensureConnected(carol, CAROL_AID);

    // Alice 创建群组
    const groupResult = await alice.call('group.create', {
      name: 'TS Gap Fill Test',
      members: [BOB_AID, CAROL_AID],
    }) as { group_id: string };
    const groupId = groupResult.group_id;
    expect(groupId).toBeTruthy();

    await new Promise(r => setTimeout(r, 1000));

    // Alice 发送 5 条群消息
    for (let i = 1; i <= 5; i++) {
      await alice.call('group.send_message', {
        group_id: groupId,
        payload: `group_msg${i}`,
        encrypt: true,
      });
      await new Promise(r => setTimeout(r, 200));
    }

    await new Promise(r => setTimeout(r, 2000));

    // Bob 拉取群消息
    const result = await bob.call('group.pull', {
      group_id: groupId,
      after_seq: 0,
      limit: 50,
    }) as { messages?: Array<{ seq: number; payload: string; from: string }> };

    const msgs = (result.messages ?? []).filter(m => m.from === ALICE_AID);
    expect(msgs.length).toBe(5);

    // 验证 seq 连续
    const seqs = msgs.map(m => m.seq);
    for (let i = 1; i < seqs.length; i++) {
      expect(seqs[i]).toBe(seqs[i - 1] + 1);
    }

    // 验证 payload 顺序
    const payloads = msgs.map(m => m.payload);
    expect(payloads).toEqual([
      'group_msg1', 'group_msg2', 'group_msg3', 'group_msg4', 'group_msg5',
    ]);
  });
});
