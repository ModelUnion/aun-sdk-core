/**
 * 消息 ACK 与在线状态集成测试 — 需要运行中的 AUN Gateway Docker 环境。
 *
 * 覆盖：
 *   - 消息 ACK 基础：发送 → pull → ack → ack_seq 推进
 *   - 消息 ACK 序列：连续 ack 按顺序推进
 *   - 在线状态：连接后在线、断开后离线、批量查询、重连恢复
 *
 * 运行方法：
 *   npx vitest run tests/integration/message-ack-online.test.ts
 *
 * 前置条件：
 *   - Docker 环境运行中（docker compose up -d）
 *   - 运行环境能解析 gateway.agentid.pub
 */

import { describe, it, expect, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { AUNClient } from '../../src/client.js';

process.env.AUN_ENV ??= 'development';

const TEST_TIMEOUT = 30_000;
const ISSUER = process.env.AUN_TEST_ISSUER ?? 'agentid.pub';
const GATEWAY_DISCOVERY_AID = process.env.AUN_TEST_GATEWAY_AID ?? `gateway.${ISSUER}`;

// ── 辅助函数 ──────────────────────────────────────────────────────

function runId(): string {
  return crypto.randomUUID().replace(/-/g, '').slice(0, 12);
}

function makeClient(): AUNClient {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-ack-'));
  const client = new AUNClient({ aun_path: tmpDir }, true);
  ((client as unknown) as { _configModel: { requireForwardSecrecy: boolean } })._configModel.requireForwardSecrecy = false;
  return client;
}

async function ensureConnected(client: AUNClient, aid: string): Promise<void> {
  const gateway = await client.auth._resolveGateway(GATEWAY_DISCOVERY_AID);
  ((client as unknown) as { _gatewayUrl: string })._gatewayUrl = gateway;
  await client.auth.createAid({ aid });
  const auth = await client.auth.authenticate({ aid });
  await client.connect(auth);
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function payloadText(message: Record<string, unknown>): string {
  const payload = message.payload as Record<string, unknown> | undefined;
  return String(payload?.text ?? '');
}

function waitForP2pMessages(
  client: AUNClient,
  fromAid: string,
  expectedCount: number,
  timeoutMs: number,
  predicate?: (message: Record<string, unknown>) => boolean,
): Promise<Record<string, unknown>[]> {
  const inbox: Record<string, unknown>[] = [];
  let sub: { unsubscribe: () => void } | null = null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let done = false;

  return new Promise(resolve => {
    const finish = () => {
      if (done) return;
      done = true;
      if (timer) clearTimeout(timer);
      sub?.unsubscribe();
      resolve(inbox);
    };

    sub = client.on('message.received', (data: unknown) => {
      if (typeof data !== 'object' || data === null) return;
      const message = data as Record<string, unknown>;
      if (message.from !== fromAid) return;
      if (predicate && !predicate(message)) return;
      inbox.push(message);
      if (inbox.length >= expectedCount) finish();
    });

    timer = setTimeout(finish, timeoutMs);
  });
}

// ── 消息 ACK 基础 ──────────────────────────────────────────────────

describe('消息 ACK 基础', () => {
  it('发送消息后 ack 应推进 ack_seq', async () => {
    const rid = runId();
    const aliceAid = `acka${rid}.${ISSUER}`;
    const bobAid = `ackb${rid}.${ISSUER}`;

    const alice = makeClient();
    const bob = makeClient();

    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(bob, bobAid);

      const text = `ack-basic-${rid}`;
      const pushed = waitForP2pMessages(
        bob,
        aliceAid,
        1,
        10_000,
        message => payloadText(message) === text,
      );

      // Alice 发送一条持久消息给 Bob
      const sendResult = await alice.call('message.send', {
        to: bobAid,
        payload: { type: 'text', text },
        durable: true,
        encrypt: false,
      }) as Record<string, unknown>;

      const messages = await pushed;
      expect(messages.length).toBe(1);
      const ackTargetSeq = Number(messages[0]?.seq ?? sendResult?.seq ?? 0);
      expect(ackTargetSeq).toBeGreaterThan(0);

      // Bob 确认消息
      const ackResult = await bob.call('message.ack', {
        seq: ackTargetSeq,
      }) as Record<string, unknown>;

      expect(ackResult?.success).toBe(true);
      expect(ackResult?.ack_seq).toBeDefined();
      expect(Number(ackResult?.ack_seq)).toBeGreaterThanOrEqual(ackTargetSeq);
    } finally {
      await alice.close();
      await bob.close();
    }
  }, 60_000);
});

// ── 消息 ACK 序列 ──────────────────────────────────────────────────

describe('消息 ACK 序列', () => {
  it('连续 ack 应按顺序推进', async () => {
    const rid = runId();
    const aliceAid = `acksa${rid}.${ISSUER}`;
    const bobAid = `acksb${rid}.${ISSUER}`;

    const alice = makeClient();
    const bob = makeClient();

    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(bob, bobAid);

      // Alice 连续发送 3 条消息
      const msgCount = 3;
      const pushed = waitForP2pMessages(
        bob,
        aliceAid,
        msgCount,
        15_000,
        message => payloadText(message).startsWith(`ack-seq-${rid}-`),
      );
      for (let i = 0; i < msgCount; i++) {
        await alice.call('message.send', {
          to: bobAid,
          payload: { type: 'text', text: `ack-seq-${rid}-${i}` },
          durable: true,
          encrypt: false,
        });
        await sleep(100);
      }

      const messages = (await pushed)
        .sort((a, b) => Number(a.seq ?? 0) - Number(b.seq ?? 0));
      if (messages.length < msgCount) {
        console.log(`Bob 只收到 ${messages.length}/${msgCount} 条推送消息`);
      }
      expect(messages.length).toBeGreaterThanOrEqual(msgCount);

      // 按顺序 ack 每条消息，验证 ack_seq 单调递增
      let prevAckSeq = -1;
      for (const msg of messages) {
        const seq = msg.seq as number;
        if (seq === undefined) continue;

        const ackResult = await bob.call('message.ack', {
          seq,
        }) as Record<string, unknown>;

        expect(ackResult?.success).toBe(true);
        const currentAckSeq = Number(ackResult?.ack_seq);
        expect(currentAckSeq).toBeGreaterThanOrEqual(seq);

        if (prevAckSeq >= 0) {
          // ack_seq 应单调递增
          expect(currentAckSeq).toBeGreaterThanOrEqual(prevAckSeq);
        }
        prevAckSeq = currentAckSeq;
      }

      console.log(`连续 ack ${messages.length} 条消息完成，最终 ack_seq=${prevAckSeq}`);
    } finally {
      await alice.close();
      await bob.close();
    }
  }, 60_000);
});

// ── 在线状态-连接后在线 ──────────────────────────────────────────────

describe('在线状态-连接后在线', () => {
  it('连接后 query_online 应返回在线', async () => {
    const rid = runId();
    const aliceAid = `olna${rid}.${ISSUER}`;
    const bobAid = `olnb${rid}.${ISSUER}`;

    const alice = makeClient();
    const bob = makeClient();

    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(bob, bobAid);

      // 等待连接状态稳定
      await sleep(500);

      // Alice 查询 Bob 的在线状态
      const result = await alice.call('message.query_online', {
        aids: [bobAid],
      }) as Record<string, unknown>;

      const online = result?.online as Record<string, boolean>;
      expect(online).toBeDefined();
      expect(online[bobAid]).toBe(true);
    } finally {
      await alice.close();
      await bob.close();
    }
  }, 60_000);
});

// ── 在线状态-断开后离线 ──────────────────────────────────────────────

describe('在线状态-断开后离线', () => {
  it('断开后 query_online 应返回离线', async () => {
    const rid = runId();
    const aliceAid = `offa${rid}.${ISSUER}`;
    const bobAid = `offb${rid}.${ISSUER}`;

    const alice = makeClient();
    const bob = makeClient();

    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(bob, bobAid);

      await sleep(500);

      // 先确认 Bob 在线
      const beforeResult = await alice.call('message.query_online', {
        aids: [bobAid],
      }) as Record<string, unknown>;
      const beforeOnline = beforeResult?.online as Record<string, boolean>;
      expect(beforeOnline?.[bobAid]).toBe(true);

      // Bob 断开连接
      await bob.disconnect();

      // 轮询等待 Alice 看到 Bob 离线（最多 10 秒）
      let offline = false;
      for (let i = 0; i < 34; i++) {
        await sleep(300);
        const pollResult = await alice.call('message.query_online', {
          aids: [bobAid],
        }) as Record<string, unknown>;
        const pollOnline = pollResult?.online as Record<string, boolean>;
        if (pollOnline?.[bobAid] === false) {
          offline = true;
          break;
        }
      }

      expect(offline).toBe(true);
    } finally {
      await alice.close();
      await bob.close();
    }
  }, 60_000);
});

// ── 在线状态-批量查询 ──────────────────────────────────────────────

describe('在线状态-批量查询', () => {
  it('批量查询应正确反映各 AID 在线状态', async () => {
    const rid = runId();
    const aliceAid = `btcha${rid}.${ISSUER}`;
    const bobAid = `btchb${rid}.${ISSUER}`;
    const charlieAid = `btchc${rid}.${ISSUER}`;

    const alice = makeClient();
    const bob = makeClient();
    const charlie = makeClient();

    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(bob, bobAid);
      // Charlie 只创建 AID 但不连接（或连接后断开）
      await ensureConnected(charlie, charlieAid);
      await charlie.disconnect();

      // 等待断开状态传播
      await sleep(1_000);

      // 轮询等待 Charlie 离线状态收敛（最多 10 秒）
      let converged = false;
      for (let i = 0; i < 34; i++) {
        const result = await alice.call('message.query_online', {
          aids: [bobAid, charlieAid],
        }) as Record<string, unknown>;
        const online = result?.online as Record<string, boolean>;

        if (online?.[bobAid] === true && online?.[charlieAid] === false) {
          converged = true;
          console.log(`批量查询结果正确: bob=在线, charlie=离线`);
          break;
        }
        await sleep(300);
      }

      expect(converged).toBe(true);
    } finally {
      await alice.close();
      await bob.close();
      await charlie.close();
    }
  }, 60_000);
});

// ── 在线状态-重连恢复 ──────────────────────────────────────────────

describe('在线状态-重连恢复', () => {
  it('断开重连后应恢复在线', async () => {
    const rid = runId();
    const aliceAid = `rcona${rid}.${ISSUER}`;
    const bobAid = `rconb${rid}.${ISSUER}`;

    const alice = makeClient();
    const bob = makeClient();

    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(bob, bobAid);

      await sleep(500);

      // 确认 Bob 初始在线
      const initResult = await alice.call('message.query_online', {
        aids: [bobAid],
      }) as Record<string, unknown>;
      expect((initResult?.online as Record<string, boolean>)?.[bobAid]).toBe(true);

      // Bob 断开
      await bob.disconnect();

      // 等待离线状态收敛
      let wentOffline = false;
      for (let i = 0; i < 34; i++) {
        await sleep(300);
        const pollResult = await alice.call('message.query_online', {
          aids: [bobAid],
        }) as Record<string, unknown>;
        if ((pollResult?.online as Record<string, boolean>)?.[bobAid] === false) {
          wentOffline = true;
          break;
        }
      }
      expect(wentOffline).toBe(true);

      // Bob 使用同一本地身份重连
      const auth = await bob.auth.authenticate({ aid: bobAid });
      await bob.connect(auth);

      // 轮询等待 Bob 重新上线（最多 10 秒）
      let backOnline = false;
      for (let i = 0; i < 34; i++) {
        await sleep(300);
        const pollResult = await alice.call('message.query_online', {
          aids: [bobAid],
        }) as Record<string, unknown>;
        if ((pollResult?.online as Record<string, boolean>)?.[bobAid] === true) {
          backOnline = true;
          break;
        }
      }

      expect(backOnline).toBe(true);
      console.log('Bob 断开重连后恢复在线');
    } finally {
      await alice.close();
      await bob.close();
    }
  }, 60_000);
});
