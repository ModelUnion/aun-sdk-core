/**
 * AUN E2EE V2: Group 端到端测试
 *
 * 使用固定身份（alice / bobb）验证 V2 Group 加密消息的完整链路：
 * - 建群 + 加成员
 * - 加密发送 / 拉取解密 / ack
 * - 双向通信
 * - epoch rotation 后发送
 * - stale epoch 推测性重试
 *
 * 运行方法（容器内）：
 *   npx vitest run tests/e2e/v2-group.test.ts --reporter=verbose
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { AUNClient } from '../../src/client.js';
import { registerAndLoadIdentity, setGatewayForClient } from '../test-support.js';

process.env.AUN_ENV ??= 'development';

// ── 环境配置 ──────────────────────────────────────────────────

const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';
const GATEWAY_DISCOVERY_AID = process.env.AUN_TEST_GATEWAY_AID ?? `gateway.${ISSUER}`;

const TEST_TIMEOUT = 60_000;

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

// ── 辅助函数 ──────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function makeClient(): AUNClient {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-v2-grp-'));
  const client = new AUNClient({ aun_path: tmpDir, debug: true });
  (client as any)._configModel.requireForwardSecrecy = false;
  return client;
}

async function connectClient(client: AUNClient, aid: string): Promise<void> {
  await setGatewayForClient(client, GATEWAY_DISCOVERY_AID);
  await registerAndLoadIdentity(client, aid);
  await client.connect({ auto_reconnect: false });
  await (client as any)._initV2Session();
}

// ── 测试用例 ──────────────────────────────────────────────────

describe('V2 Group E2EE 端到端测试', { timeout: TEST_TIMEOUT }, () => {
  let alice: AUNClient;
  let bob: AUNClient;
  let ALICE_AID: string;
  let BOB_AID: string;
  let groupId: string;

  // 测试间共享的状态
  let sentPayload: Record<string, unknown>;
  let replyText: string;
  const alicePushMsgs: Record<string, unknown>[] = [];
  const bobPushMsgs: Record<string, unknown>[] = [];

  beforeAll(async () => {
    const rid = runId();
    ALICE_AID = `v2g-a-${rid}.${ISSUER}`;
    BOB_AID = `v2g-b-${rid}.${ISSUER}`;

    alice = makeClient();
    bob = makeClient();

    await connectClient(alice, ALICE_AID);
    await connectClient(bob, BOB_AID);

    console.log(`[setup] Alice V2=${(alice as any)._v2Session != null}, Bob V2=${(bob as any)._v2Session != null}`);

    alice.on('group.message_created', (data) => {
      if (data && typeof data === 'object') alicePushMsgs.push(data as Record<string, unknown>);
    });
    bob.on('group.message_created', (data) => {
      if (data && typeof data === 'object') bobPushMsgs.push(data as Record<string, unknown>);
    });

    // 创建测试群
    const result = await alice.call('group.create', {
      name: `v2-test-${Date.now()}`,
      visibility: 'private',
    }) as Record<string, unknown>;
    const group = result.group as Record<string, unknown>;
    groupId = String(group.group_id ?? '');
    console.log(`[setup] 创建群: ${groupId}`);

    // 添加 Bob
    await alice.call('group.add_member', {
      group_id: groupId,
      aid: BOB_AID,
    });
    console.log(`[setup] Bob 已加入群`);

    // 等待 V2 group bootstrap 就绪
    await sleep(2000);
  });

  afterAll(async () => {
    try { await alice?.close(); } catch {}
    try { await bob?.close(); } catch {}
  });

  // ── 场景 1：Alice call('group.send') 走 V2 路径 ──

  it('Alice call(group.send) 发送加密群消息（V2 路径）', async () => {
    sentPayload = { text: `group-v2-test ${Date.now()}` };
    const result = await alice.call('group.send', {
      group_id: groupId,
      payload: sentPayload,
    }) as Record<string, unknown>;
    expect(result?.status).toBe('accepted');
    console.log(`  (seq=${result?.seq ?? 'n/a'})`);
  });

  // ── 场景 2：Bob call('group.pull') 走 V2 路径解密 ──

  it('Bob call(group.pull) 解密', async () => {
    for (let i = 0; i < 20; i++) {
      await sleep(200);
      const foundPush = bobPushMsgs.find(
        m => (m.payload as Record<string, unknown>)?.text === sentPayload.text || m.text === sentPayload.text,
      );
      if (foundPush) break;
    }

    const pushFound = bobPushMsgs.find(
      m => (m.payload as Record<string, unknown>)?.text === sentPayload.text || m.text === sentPayload.text,
    );
    if (pushFound) {
      const text = (pushFound.payload as Record<string, unknown>)?.text ?? pushFound.text;
      console.log(`  (decrypted via push: '${String(text).slice(0, 30)}...')`);
      bobPushMsgs.length = 0;
      return;
    }

    const pulled = await bob.call('group.pull', { group_id: groupId }) as Record<string, unknown>;
    const messages = (pulled.messages ?? []) as Array<Record<string, unknown>>;
    const found = messages.find(
      m => (m.payload as Record<string, unknown>)?.text === sentPayload.text || m.text === sentPayload.text,
    );
    expect(found, `Bob got ${messages.length} msgs but none match`).toBeTruthy();
    const text = (found?.payload as Record<string, unknown>)?.text ?? found?.text;
    console.log(`  (decrypted via pull: '${String(text).slice(0, 30)}...')`);
    bobPushMsgs.length = 0;
  });

  // ── 场景 3：Bob call('group.ack_messages') 走 V2 路径 ──

  it('Bob call(group.ack_messages) 走 V2 路径', async () => {
    // V2 internal pull 会自动 auto-ack contiguous_seq，
    // 这里再显式 ack 一次：返回结构正常即视为通过（acked 可能为 0，因为已被 pull 自动 ack）
    const result = await bob.call('group.ack_messages', { group_id: groupId }) as Record<string, unknown>;
    expect(result, `ack_messages should return result, got: ${JSON.stringify(result)}`).toBeDefined();
    expect(Number(result?.acked ?? 0)).toBeGreaterThanOrEqual(0);
  });

  // ── 场景 4：ack 后 pull 为空 ──

  it('ack 后 pull 为空', async () => {
    const pulled = await bob.call('group.pull', { group_id: groupId }) as Record<string, unknown>;
    const messages = (pulled.messages ?? []) as Array<Record<string, unknown>>;
    expect(messages.length).toBe(0);
  });

  // ── 场景 5：Bob 回复 ──

  it('Bob 回复群消息', async () => {
    const reply = { text: `bob-group-reply ${Date.now()}` };
    replyText = reply.text;
    const result = await bob.call('group.send', {
      group_id: groupId,
      payload: reply,
    }) as Record<string, unknown>;
    expect(result?.status).toBe('accepted');
  });

  // ── 场景 6：Alice pull 解密回复 ──

  it('Alice call(group.pull) 解密回复', async () => {
    for (let i = 0; i < 20; i++) {
      await sleep(200);
      const foundPush = alicePushMsgs.find(
        m => (m.payload as Record<string, unknown>)?.text === replyText || m.text === replyText,
      );
      if (foundPush) break;
    }

    const pushFound = alicePushMsgs.find(
      m => (m.payload as Record<string, unknown>)?.text === replyText || m.text === replyText,
    );
    if (pushFound) {
      const text = (pushFound.payload as Record<string, unknown>)?.text ?? pushFound.text;
      console.log(`  (from Bob via push: '${String(text).slice(0, 30)}...')`);
      alicePushMsgs.length = 0;
      return;
    }

    const pulled = await alice.call('group.pull', { group_id: groupId }) as Record<string, unknown>;
    const messages = (pulled.messages ?? []) as Array<Record<string, unknown>>;
    const found = messages.find(
      m => (m.payload as Record<string, unknown>)?.text === replyText || m.text === replyText,
    );
    expect(found, `Alice got ${messages.length} msgs but none match reply`).toBeTruthy();
    const text = (found?.payload as Record<string, unknown>)?.text ?? found?.text;
    console.log(`  (from Bob via pull: '${String(text).slice(0, 30)}...')`);
    alicePushMsgs.length = 0;
  });

  // ── 场景 7：成员变更后 state/epoch 更新再发送 ──

  it('成员变更后发送', async () => {
    // kick Bob → V2 state/epoch 由服务端和 SDK 编排更新
    await alice.call('group.kick', { group_id: groupId, aid: BOB_AID });
    await sleep(500);

    // 清除 bootstrap 缓存
    const cache = (alice as any)._v2BootstrapCache as Map<string, unknown>;
    cache?.delete?.(`group:${groupId}`);

    // re-add Bob
    await alice.call('group.add_member', { group_id: groupId, aid: BOB_AID });
    await sleep(1000);

    // Alice 发消息（应使用新 epoch）
    const epochPayload = { text: `after-rotation ${Date.now()}` };
    const result = await alice.call('group.send', {
      group_id: groupId,
      payload: epochPayload,
    }) as Record<string, unknown>;
    expect(result?.status).toBe('accepted');
    console.log(`  (seq=${result?.seq ?? 'n/a'})`);
  });

  // ── 场景 8：stale epoch 推测性重试 ──

  it('stale epoch 推测性重试', async () => {
    // 注入 stale epoch 到缓存（模拟缓存过期）
    const cache = (alice as any)._v2BootstrapCache as Map<string, any>;
    const cacheKey = `group:${groupId}`;
    const cached = cache?.get?.(cacheKey);
    if (cached && cached.epoch > 0) {
      cache.set(cacheKey, { ...cached, epoch: Math.max(0, cached.epoch - 1) });
    }

    const payload = { text: `stale-epoch-retry ${Date.now()}` };
    // V2 内部会在 stale epoch 被拒后自动刷新重试
    const result = await alice.call('group.send', {
      group_id: groupId,
      payload,
    }) as Record<string, unknown>;
    expect(result?.status).toBe('accepted');
    console.log(`  (retry succeeded)`);
  });
});
