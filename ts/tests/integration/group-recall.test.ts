/**
 * 群组消息撤回集成测试（TS）— 需要运行中的 AUN Gateway + Group Service。
 *
 * 基准 = Python integration_test_group_recall.py。
 * SDK 把撤回 tombstone 归一化为 group.message_recalled 事件（不在 pull 消息列表里出现），
 * 并按 (group_id, message_ids, recalled_at) 去重，应用层只回调一次。
 *
 * 运行方法：
 *   npx vitest run tests/integration/group-recall.test.ts
 */

import { describe, it, expect, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { AUNClient } from '../../src/client.js';
import { createTestClient, registerAndLoadIdentity } from '../test-support.js';

process.env.AUN_ENV ??= 'development';

const TEST_TIMEOUT = 60_000;
const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';

type JsonObject = Record<string, unknown>;

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

function makeClient(): AUNClient {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-grecall-'));
  return createTestClient({ aunPath: tmpDir, debug: true, requireForwardSecrecy: false });
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  await registerAndLoadIdentity(client, aid);
  await client.connect();
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function isNotImplemented(e: unknown): boolean {
  const msg = String((e as Error)?.message ?? e).toLowerCase();
  return msg.includes('not found') || msg.includes('not implement') || msg.includes('method');
}

/** 兼容 V2 send（顶层 message_id/seq）与明文 send（message.{message_id,seq}）。 */
function extractMsg(result: JsonObject): { id: string; seq: number } {
  const nested = result.message as JsonObject | undefined;
  if (nested && nested.message_id) {
    return { id: String(nested.message_id), seq: Number(nested.seq ?? 0) };
  }
  return { id: String(result.message_id ?? ''), seq: Number(result.seq ?? 0) };
}

describe('Group recall: 撤回群消息', () => {
  const clients: AUNClient[] = [];
  function tracked(): AUNClient {
    const c = makeClient();
    clients.push(c);
    return c;
  }
  afterEach(async () => {
    await Promise.allSettled(clients.map(c => c.close()));
    clients.length = 0;
  });

  it('发送者撤回加密群消息，member 收到 group.message_recalled 恰好一次', async () => {
    const rid = runId();
    const ownerAid = `grecall-own-${rid}.${ISSUER}`;
    const memberAid = `grecall-mem-${rid}.${ISSUER}`;
    const owner = tracked();
    const member = tracked();

    await ensureConnected(owner, ownerAid);
    await ensureConnected(member, memberAid);

    let groupId = '';
    try {
      const createResult = await owner.call('group.create', {
        name: `recall-${rid}`,
        visibility: 'private',
        group_e2ee_protocol: 'group_e2ee_v2',
      }) as JsonObject;
      groupId = String((createResult.group as JsonObject)?.group_id ?? '');
      expect(groupId).toBeTruthy();
    } catch (e) {
      if (isNotImplemented(e)) { console.log('group.create 未实现，跳过'); return; }
      throw e;
    }

    await owner.call('group.add_member', { group_id: groupId, aid: memberAid, role: 'member' });
    await sleep(2500); // 等待 epoch + state commit + bootstrap

    const recallEvents: JsonObject[] = [];
    const sub = member.on('group.message_recalled', (data) => {
      const d = data as JsonObject;
      if (String(d.group_id ?? '') === groupId) recallEvents.push(d);
    });

    // 发送加密消息
    let msgId = '';
    let origSeq = 0;
    try {
      const sendResult = await owner.call('group.send', {
        group_id: groupId,
        payload: { type: 'text', text: `recall-target-${rid}` },
        encrypt: true,
      }) as JsonObject;
      const m = extractMsg(sendResult);
      msgId = m.id;
      origSeq = m.seq;
      expect(msgId).toBeTruthy();
    } catch (e) {
      sub.unsubscribe();
      if (isNotImplemented(e)) { console.log('group.send 未实现，跳过'); return; }
      throw e;
    }

    // member 先收一次原消息（成为"已读客户端"）
    await sleep(800);
    await member.call('group.pull', { group_id: groupId, after_seq: 0, limit: 50, force: true });
    await sleep(400);

    // owner 撤回
    const recallResult = await owner.call('group.recall', {
      group_id: groupId,
      message_ids: [msgId],
    }) as JsonObject;
    const recalled = (recallResult.recalled ?? []) as string[];
    expect(recalled, `recall 应成功: ${JSON.stringify(recallResult)}`).toContain(msgId);

    // 等待推送 + member 再 pull 兜底
    await sleep(1500);
    await member.call('group.pull', { group_id: groupId, after_seq: 0, limit: 50, force: true });
    await sleep(600);
    sub.unsubscribe();

    // SDK 去重：group.message_recalled 恰好一次
    expect(recallEvents.length, `期望 1 次 recall 回调，实际 ${recallEvents.length}`).toBe(1);
    expect((recallEvents[0].message_ids as string[]) ?? []).toContain(msgId);

    // 服务端 raw 校验：双 tombstone 落库，密文已删。
    // 用 _callRawV2Rpc 直连服务端，绕过 call() 的 group.v2.pull 路由（该路由会把 tombstone 归一化掉）。
    const raw = await (member as unknown as {
      _callRawV2Rpc(method: string, params?: JsonObject): Promise<JsonObject>;
    })._callRawV2Rpc('group.v2.pull', {
      group_id: groupId, after_seq: 0, limit: 50, force: true,
    });
    const rawMsgs = (raw.messages ?? []) as JsonObject[];
    const tombstones = rawMsgs.filter(m =>
      String(m.type ?? m.message_type ?? '') === 'group.message_recalled');
    expect(tombstones.length, `期望 >=2 个 tombstone，实际 ${tombstones.length}`).toBeGreaterThanOrEqual(2);
    expect(tombstones.some(m => Number(m.seq ?? 0) === origSeq), '占位 tombstone 应在原 seq').toBe(true);
    const ciphertextPresent = rawMsgs.some(m =>
      String(m.message_id ?? '') === msgId && m.envelope_json);
    expect(ciphertextPresent, '原始密文不应再可拉取').toBe(false);

    try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
  }, TEST_TIMEOUT);

  it('非发送者撤回被拒绝（not_sender）', async () => {
    const rid = runId();
    const ownerAid = `grecall2-own-${rid}.${ISSUER}`;
    const memberAid = `grecall2-mem-${rid}.${ISSUER}`;
    const owner = tracked();
    const member = tracked();

    await ensureConnected(owner, ownerAid);
    await ensureConnected(member, memberAid);

    let groupId = '';
    try {
      const cr = await owner.call('group.create', {
        name: `recall2-${rid}`, visibility: 'private', group_e2ee_protocol: 'group_e2ee_v2',
      }) as JsonObject;
      groupId = String((cr.group as JsonObject)?.group_id ?? '');
    } catch (e) {
      if (isNotImplemented(e)) { console.log('group.create 未实现，跳过'); return; }
      throw e;
    }
    await owner.call('group.add_member', { group_id: groupId, aid: memberAid, role: 'member' });
    await sleep(2500);

    const sendResult = await owner.call('group.send', {
      group_id: groupId, payload: { type: 'text', text: 'not-sender-target' }, encrypt: true,
    }) as JsonObject;
    const { id: msgId } = extractMsg(sendResult);
    await sleep(500);

    // member（非发送者）尝试撤回 → not_sender
    const r = await member.call('group.recall', { group_id: groupId, message_ids: [msgId] }) as JsonObject;
    const errors = (r.errors ?? []) as JsonObject[];
    expect(errors.some(e => String(e.error ?? '') === 'not_sender'),
      `期望 not_sender, 实际 ${JSON.stringify(r)}`).toBe(true);

    try { await owner.call('group.dissolve', { group_id: groupId }); } catch { /* 忽略 */ }
  }, TEST_TIMEOUT);
});
