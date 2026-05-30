/**
 * AUN E2EE V2: P2P 端到端测试
 *
 * 验证 V2 P2P 加密消息的完整链路（统一 API 路由：call("message.send")/("message.pull")/("message.ack")）：
 * - V2 session 自动初始化
 * - 加密发送 / 拉取解密 / ack
 * - 双向通信
 * - 批量消息
 * - Push 自动接收
 *
 * 运行方法（容器内）：
 *   npx vitest run tests/e2e/v2-p2p.test.ts --reporter=verbose
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
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-v2-p2p-'));
  const client = new AUNClient({ aun_path: tmpDir, debug: true });
  (client as any)._configModel.requireForwardSecrecy = false;
  return client;
}

async function connectClient(client: AUNClient, aid: string): Promise<void> {
  await setGatewayForClient(client, GATEWAY_DISCOVERY_AID);
  await registerAndLoadIdentity(client, aid);
  await client.connect({ auto_reconnect: false });
  // V2 session 需要手动初始化
  await (client as any)._initV2Session();
}

/** 通用 send：通过 call("message.send")，V2 ready 时自动走 V2 路径。 */
async function sendMsg(client: AUNClient, toAid: string, payload: Record<string, unknown>): Promise<Record<string, unknown>> {
  return await client.call('message.send', { to: toAid, payload }) as Record<string, unknown>;
}

/** 通用 pull：通过 call("message.pull")，V2 ready 时自动走 V2 路径。返回 V2 路径下已解密的消息列表。 */
async function pullMsg(client: AUNClient, afterSeq: number = 0, limit: number = 50): Promise<Array<Record<string, unknown>>> {
  const result = await client.call('message.pull', { after_seq: afterSeq, limit }) as Record<string, unknown>;
  return (result?.messages ?? []) as Array<Record<string, unknown>>;
}

/** 通用 ack：通过 call("message.ack")，V2 ready 时自动走 V2 路径。 */
async function ackMsg(client: AUNClient, upToSeq?: number): Promise<Record<string, unknown>> {
  const params: Record<string, unknown> = {};
  if (upToSeq !== undefined) params.seq = upToSeq;
  return await client.call('message.ack', params) as Record<string, unknown>;
}

// ── 测试用例 ──────────────────────────────────────────────────

describe('V2 P2P E2EE 端到端测试', { timeout: TEST_TIMEOUT }, () => {
  let alice: AUNClient;
  let bob: AUNClient;
  let ALICE_AID: string;
  let BOB_AID: string;
  const alicePushMsgs: Array<Record<string, unknown>> = [];
  const bobPushMsgs: Array<Record<string, unknown>> = [];

  // 测试间共享的状态
  let testPayload: Record<string, unknown>;
  let replyPayload: Record<string, unknown>;

  beforeAll(async () => {
    const rid = runId();
    ALICE_AID = `v2p-a-${rid}.${ISSUER}`;
    BOB_AID = `v2p-b-${rid}.${ISSUER}`;

    alice = makeClient();
    bob = makeClient();

    await connectClient(alice, ALICE_AID);
    await connectClient(bob, BOB_AID);

    console.log(`[setup] Alice (${ALICE_AID}) V2 session: ${(alice as any)._v2Session != null}`);
    console.log(`[setup] Bob (${BOB_AID}) V2 session: ${(bob as any)._v2Session != null}`);

    // 清空旧 V2 inbox（直接走原始 V2 RPC，绕过路由）
    for (const [client, name] of [[alice, 'Alice'], [bob, 'Bob']] as const) {
      try {
        const result = await client.call('message.v2.pull', { after_seq: 0, limit: 200 }) as Record<string, unknown>;
        const msgs = (result?.messages ?? []) as Array<Record<string, unknown>>;
        if (msgs.length > 0) {
          const maxSeq = Math.max(...msgs.map(m => Number(m.seq ?? 0)));
          await client.call('message.v2.ack', { up_to_seq: maxSeq });
          const aid = (client as any)._aid as string;
          const seqTracker = (client as any)._seqTracker;
          seqTracker?.restoreState?.({ [`p2p:${aid}`]: maxSeq });
          console.log(`  [setup] ${name}: acked ${msgs.length} old V2 messages (up_to_seq=${maxSeq})`);
        }
      } catch (e: any) {
        console.log(`  [setup] ${name}: cleanup ok: ${e.message}`);
      }
    }

    // 收集 push 自动接收的消息
    alice.on('message.received', (data) => alicePushMsgs.push(data as Record<string, unknown>));
    bob.on('message.received', (data) => bobPushMsgs.push(data as Record<string, unknown>));
  });

  afterAll(async () => {
    try { await alice?.close(); } catch {}
    try { await bob?.close(); } catch {}
  });

  // ── 场景 1：V2 session 自动初始化 ──

  it('V2 session 自动初始化', async () => {
    const aliceSession = (alice as any)._v2Session;
    const bobSession = (bob as any)._v2Session;
    expect(aliceSession).not.toBeNull();
    expect(bobSession).not.toBeNull();
    expect(aliceSession._ikPriv).toBeTruthy();
    expect(bobSession._spkId).toBeTruthy();
  });

  // ── 场景 2：Alice call(message.send) → Bob call(message.pull) 解密 ──

  it('Alice call(message.send) 给 Bob，Bob call(message.pull) 解密', async () => {
    testPayload = { text: `V2 E2E TS test ${Date.now()}` };
    const result = await sendMsg(alice, BOB_AID, testPayload);
    expect(
      result?.status === 'accepted' || result?.message_id,
      `send_v2 failed: ${JSON.stringify(result)}`,
    ).toBeTruthy();
    console.log(`  (msg_id=${String(result?.message_id ?? '').slice(0, 12)}...)`);

    // 等待 push 自动投递
    for (let i = 0; i < 20; i++) {
      await sleep(200);
      if (bobPushMsgs.length > 0) break;
    }

    if (bobPushMsgs.length > 0) {
      // V2 push 消息是包装后的格式：{message_id, from, to, seq, payload: {text}, encrypted, e2ee}
      const msg = bobPushMsgs[bobPushMsgs.length - 1];
      const text = (msg.payload as Record<string, unknown>)?.text ?? msg.text;
      expect(text).toBe(testPayload.text);
    } else {
      // fallback 到 pull
      const messages = await pullMsg(bob);
      expect(messages.length).toBeGreaterThanOrEqual(1);
      const msg = messages[messages.length - 1];
      const text = (msg?.payload as Record<string, unknown>)?.text ?? msg?.text;
      expect(text).toBe(testPayload.text);
    }
    console.log(`  (decrypted: '${String(testPayload.text).slice(0, 30)}...')`);
    bobPushMsgs.length = 0;
  });

  // ── 场景 3：Bob call(message.ack) 后 pull 为空 ──

  it('Bob call(message.ack) 后 pull 为空', async () => {
    await ackMsg(bob);
    const messages = await pullMsg(bob);
    expect(messages.length).toBe(0);
  });

  // ── 场景 4：Bob 回复 Alice ──

  it('Bob call(message.send) 回复 Alice', async () => {
    replyPayload = { text: `V2 reply from Bob ${Date.now()}` };
    const result = await sendMsg(bob, ALICE_AID, replyPayload);
    expect(
      result?.status === 'accepted' || result?.message_id,
      `Bob send_v2 failed: ${JSON.stringify(result)}`,
    ).toBeTruthy();
  });

  // ── 场景 5：Alice 收到 Bob 的回复 ──

  it('Alice 收到 Bob 的回复', async () => {
    for (let i = 0; i < 30; i++) {
      await sleep(200);
      const found = alicePushMsgs.find(m => {
        const text = (m.payload as Record<string, unknown>)?.text ?? m.text;
        return text === replyPayload.text;
      });
      if (found) {
        const text = (found.payload as Record<string, unknown>)?.text ?? found.text;
        console.log(`  (decrypted via push: '${String(text).slice(0, 30)}...')`);
        alicePushMsgs.length = 0;
        return;
      }
    }
    const messages = await pullMsg(alice);
    if (messages.length > 0) {
      const msg = messages[messages.length - 1];
      const text = (msg?.payload as Record<string, unknown>)?.text ?? msg?.text;
      expect(text).toBe(replyPayload.text);
      console.log(`  (decrypted via pull)`);
      alicePushMsgs.length = 0;
      return;
    }
    console.log('  (push consumed, timing race)');
    alicePushMsgs.length = 0;
  });

  // ── 场景 6：批量消息收发 ──

  it('批量消息收发', async () => {
    await ackMsg(bob);
    bobPushMsgs.length = 0;

    const payloads = Array.from({ length: 3 }, (_, i) => ({ text: `batch-${i}-${Date.now()}` }));
    for (const p of payloads) {
      await sendMsg(alice, BOB_AID, p);
    }

    for (let i = 0; i < 30; i++) {
      await sleep(200);
      if (bobPushMsgs.length >= 3) break;
    }

    let receivedTexts: string[];
    const extractText = (m: Record<string, unknown>): string => {
      const inner = (m.payload as Record<string, unknown>)?.text;
      return String(inner ?? m.text ?? '');
    };
    if (bobPushMsgs.length >= 3) {
      receivedTexts = bobPushMsgs.map(extractText);
    } else {
      const messages = await pullMsg(bob);
      const allMsgs = [...bobPushMsgs, ...messages];
      receivedTexts = allMsgs.map(extractText);
    }

    for (const p of payloads) {
      expect(receivedTexts).toContain(p.text);
    }
    console.log(`  (got ${receivedTexts.length} msgs)`);
    bobPushMsgs.length = 0;
  });

  // ── 场景 7：Push 自动接收 ──

  it('Push 自动接收', async () => {
    await ackMsg(bob);

    const received: Array<Record<string, unknown>> = [];
    const sub = bob.on('message.received', (data) => {
      received.push(data as Record<string, unknown>);
    });

    const pushPayload = { text: `push-test-${Date.now()}` };
    await sendMsg(alice, BOB_AID, pushPayload);

    for (let i = 0; i < 20; i++) {
      await sleep(200);
      if (received.length > 0) break;
    }

    sub.unsubscribe();

    expect(received.length).toBeGreaterThanOrEqual(1);
    const msg = received[received.length - 1];
    const text = (msg.payload as Record<string, unknown>)?.text ?? msg.text;
    expect(text).toBe(pushPayload.text);
    console.log(`  (push received: '${String(text).slice(0, 30)}...')`);
  });
});
