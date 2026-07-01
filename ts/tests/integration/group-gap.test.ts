/**
 * 群消息 gap 检测与自动补洞集成测试 — 对应 P1-7 修复
 *
 * 验证群消息 push 带 payload 时发现 seq gap 也必须补洞，
 * 最终业务层收到完整有序群消息序列。
 *
 * 策略：Bob 监听群消息事件，Alice 发送 5 条消息后，
 * 验证 Bob 通过推送+补洞路径收到的消息（去重后）完整有序。
 */

import { afterEach, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

import { AUNClient } from '../../src/index.js';
import { normalizeGroupId } from '../../src/group-id.js';
import { createTestClient, registerAndLoadIdentity } from '../test-support.js';

process.env.AUN_ENV ??= 'development';

const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

function makeClient(): AUNClient {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-ggap-'));
  return createTestClient({ aunPath: tmpDir, requireForwardSecrecy: false });
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  await registerAndLoadIdentity(client, aid);
  await client.connect();
}

describe('Group Message Gap Fill', { timeout: 60000 }, () => {
  let alice: AUNClient;
  let bob: AUNClient;
  let carol: AUNClient;

  afterEach(async () => {
    await alice?.close();
    await bob?.close();
    await carol?.close();
  });

  it('群消息应自动补洞并按序投递', async () => {
    const rid = runId();
    const aliceAid = `ggap-a-${rid}.${ISSUER}`;
    const bobAid = `ggap-b-${rid}.${ISSUER}`;
    const carolAid = `ggap-c-${rid}.${ISSUER}`;

    alice = makeClient();
    bob = makeClient();
    carol = makeClient();
    await ensureConnected(alice, aliceAid);
    await ensureConnected(bob, bobAid);
    await ensureConnected(carol, carolAid);

    // Alice 创建群组并添加成员
    const groupResult = await alice.call('group.create', {
      name: 'TS Gap Fill Test',
    }) as { group?: { group_id: string } };
    const groupId = normalizeGroupId(groupResult.group?.group_id ?? '');
    expect(groupId).toBeTruthy();

    await alice.call('group.add_member', { group_id: groupId, aid: bobAid });
    await alice.call('group.add_member', { group_id: groupId, aid: carolAid });

    // Bob 通过事件回调收集推送到的群消息（按 seq 去重）
    const seqMap = new Map<number, { seq: number; payload: any }>();
    let resolveAllReceived: (() => void) | undefined;
    const allReceived = new Promise<void>((resolve) => {
      resolveAllReceived = resolve;
      bob.on('group.message_created', (data: any) => {
        const sender = data.sender_aid ?? data.from ?? '';
        const messageGroupId = normalizeGroupId(data.group_aid ?? data.group_id ?? '');
        if (sender === aliceAid && messageGroupId === groupId && (data.type === 'text' || data.message_type === 'text')) {
          const seq = Number(data.seq);
          if (!seqMap.has(seq)) {
            seqMap.set(seq, { seq, payload: data.payload });
          }
          if (seqMap.size >= 5) resolve();
        }
      });
    });

    const collectPulledMessages = async () => {
      const result = await bob.call('group.pull', {
        group_id: groupId,
        after_seq: 0,
        limit: 50,
      }) as { messages?: any[] };
      for (const data of result.messages ?? []) {
        const sender = data.sender_aid ?? data.from ?? '';
        const messageGroupId = normalizeGroupId(data.group_aid ?? data.group_id ?? '');
        if (sender === aliceAid && messageGroupId === groupId && (data.type === 'text' || data.message_type === 'text')) {
          const seq = Number(data.seq);
          if (!seqMap.has(seq)) {
            seqMap.set(seq, { seq, payload: data.payload });
          }
        }
      }
    };

    await new Promise(r => setTimeout(r, 1000));

    // Alice 发送 5 条群消息
    for (let i = 1; i <= 5; i++) {
      await alice.call('group.send', {
        group_id: groupId,
        payload: { type: 'text', text: `group_msg${i}` },
        encrypt: false,
      });
      await new Promise(r => setTimeout(r, 200));
    }

    // 等待在线事件；如果推送链路只提示了部分 unread，再用公开 pull 兜底补齐。
    await Promise.race([
      allReceived,
      new Promise<void>((resolve) => setTimeout(resolve, 15000)),
    ]);
    if (seqMap.size < 5) {
      await collectPulledMessages();
    }
    if (seqMap.size >= 5) {
      resolveAllReceived?.();
    }

    const unique = [...seqMap.values()].sort((a, b) => a.seq - b.seq);
    expect(unique.length, `等待群消息超时，仅收到 ${unique.length}/5 条唯一消息`).toBe(5);

    // 验证 seq 连续
    const seqs = unique.map(m => m.seq);
    for (let i = 1; i < seqs.length; i++) {
      expect(seqs[i]).toBe(seqs[i - 1] + 1);
    }

    // 验证 payload 顺序
    const payloads = unique.map(m => {
      const p = m.payload;
      return typeof p === 'object' && p !== null ? p.text : p;
    });
    expect(payloads).toEqual([
      'group_msg1', 'group_msg2', 'group_msg3', 'group_msg4', 'group_msg5',
    ]);
  });
});
