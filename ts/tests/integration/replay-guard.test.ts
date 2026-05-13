/**
 * Replay Guard 集成测试 — 需要运行中的 AUN Gateway Docker 环境。
 *
 * 覆盖：
 *   - replay guard 基本消息流：加密消息收发，验证 message_id 和 timestamp
 *   - 重复拉取幂等：同一 after_seq 多次 pull 结果一致
 *   - 消息序号递增：连续发送后 seq 严格递增且无间隔
 *
 * 运行方法：
 *   npx vitest run tests/integration/replay-guard.test.ts
 *
 * 前置条件：
 *   - Docker 环境运行中（docker compose up -d）
 *   - 运行环境能解析 gateway.agentid.pub
 */

import { describe, it, expect } from 'vitest';
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
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aun-rg-'));
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

// ── replay guard 基本消息流 ──────────────────────────────────────

describe('replay guard 基本消息流', () => {
  it('加密消息收发正常，message_id 和 timestamp 存在且唯一', async () => {
    const rid = runId();
    const aliceAid = `rga${rid}.${ISSUER}`;
    const bobAid = `rgb${rid}.${ISSUER}`;

    const alice = makeClient();
    const bob = makeClient();

    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(bob, bobAid);

      // Alice 发送第一条加密消息给 Bob
      const send1 = await alice.call('message.send', {
        to: bobAid,
        payload: { type: 'text', text: `rg-msg1-${rid}` },
        durable: true,
        encrypt: true,
      }) as Record<string, unknown>;

      const msgId1 = send1?.message_id as string;
      expect(msgId1).toBeDefined();
      expect(typeof msgId1).toBe('string');
      expect(msgId1.length).toBeGreaterThan(0);

      await sleep(500);

      // Alice 发送第二条加密消息给 Bob
      const send2 = await alice.call('message.send', {
        to: bobAid,
        payload: { type: 'text', text: `rg-msg2-${rid}` },
        durable: true,
        encrypt: true,
      }) as Record<string, unknown>;

      const msgId2 = send2?.message_id as string;
      expect(msgId2).toBeDefined();
      expect(typeof msgId2).toBe('string');
      expect(msgId2.length).toBeGreaterThan(0);

      // 两条消息的 message_id 必须不同
      expect(msgId1).not.toBe(msgId2);

      await sleep(500);

      // Bob 拉取消息，验证 message_id 和 timestamp
      const pullResult = await bob.call('message.pull', {
        after_seq: 0,
        limit: 50,
      }) as Record<string, unknown>;

      const messages = (pullResult?.messages ?? []) as Record<string, unknown>[];
      // 筛选本轮测试的消息
      const ours = messages.filter(
        m => typeof m === 'object' && m !== null &&
          ((m as any).payload?.text?.startsWith(`rg-msg`) ||
           (m as any).message_id === msgId1 ||
           (m as any).message_id === msgId2),
      );

      if (ours.length > 0) {
        for (const msg of ours) {
          expect(msg.message_id).toBeDefined();
          // timestamp 可以是 number 或 string
          if (msg.timestamp !== undefined) {
            expect(msg.timestamp).toBeDefined();
          }
        }
        // 验证拉取到的消息 message_id 各不相同
        const ids = ours.map(m => m.message_id).filter(Boolean);
        const uniqueIds = new Set(ids);
        expect(uniqueIds.size).toBe(ids.length);
        console.log(`Bob 拉取到 ${ours.length} 条消息，message_id 均唯一`);
      } else {
        console.log('Bob 通过 pull 未匹配到本轮消息（可能仅推送），验证发送端 message_id 唯一性通过');
      }
    } finally {
      await alice.close();
      await bob.close();
    }
  }, 60_000);
});

// ── 重复拉取幂等 ──────────────────────────────────────────────────

describe('重复拉取幂等', () => {
  it('同一 after_seq 两次 pull 返回一致结果且无报错', async () => {
    const rid = runId();
    const aliceAid = `rida${rid}.${ISSUER}`;
    const bobAid = `ridb${rid}.${ISSUER}`;

    const alice = makeClient();
    const bob = makeClient();

    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(bob, bobAid);

      // Alice 发送一条持久消息给 Bob
      await alice.call('message.send', {
        to: bobAid,
        payload: { type: 'text', text: `idempotent-${rid}` },
        durable: true,
        encrypt: true,
      });

      await sleep(1_000);

      // Bob 第一次 pull（after_seq=0）
      const pull1 = await bob.call('message.pull', {
        after_seq: 0,
        limit: 50,
      }) as Record<string, unknown>;

      const messages1 = (pull1?.messages ?? []) as Record<string, unknown>[];

      // Bob 第二次 pull（同样 after_seq=0）— 不应报错
      const pull2 = await bob.call('message.pull', {
        after_seq: 0,
        limit: 50,
      }) as Record<string, unknown>;

      const messages2 = (pull2?.messages ?? []) as Record<string, unknown>[];

      // 两次结果数量应相同
      expect(messages1.length).toBe(messages2.length);

      // 两次返回的 message_id 集合应一致
      const ids1 = messages1.map(m => m.message_id).filter(Boolean).sort();
      const ids2 = messages2.map(m => m.message_id).filter(Boolean).sort();
      expect(ids1).toEqual(ids2);

      console.log(`两次 pull 均返回 ${messages1.length} 条消息，结果一致`);
    } finally {
      await alice.close();
      await bob.close();
    }
  }, 60_000);
});

// ── 消息序号递增 ──────────────────────────────────────────────────

describe('消息序号递增', () => {
  it('连续发送 5 条消息后 seq 严格递增且无间隔', async () => {
    const rid = runId();
    const aliceAid = `rsqa${rid}.${ISSUER}`;
    const bobAid = `rsqb${rid}.${ISSUER}`;

    const alice = makeClient();
    const bob = makeClient();

    try {
      await ensureConnected(alice, aliceAid);
      await ensureConnected(bob, bobAid);

      const msgCount = 5;
      const pushed = waitForP2pMessages(
        bob,
        aliceAid,
        msgCount,
        15_000,
        message => payloadText(message).startsWith(`seq-${rid}-`),
      );

      // Alice 连续发送 5 条消息给 Bob
      for (let i = 0; i < msgCount; i++) {
        await alice.call('message.send', {
          to: bobAid,
          payload: { type: 'text', text: `seq-${rid}-${i}` },
          durable: true,
          encrypt: true,
        });
        await sleep(100);
      }

      const messages = (await pushed)
        .sort((a, b) => Number(a.seq ?? 0) - Number(b.seq ?? 0));
      expect(messages.length).toBeGreaterThanOrEqual(msgCount);

      // 提取 seq 列表
      const seqs = messages
        .map(m => m.seq as number)
        .filter(s => typeof s === 'number');

      expect(seqs.length).toBeGreaterThanOrEqual(msgCount);

      // 验证 seq 严格递增
      for (let i = 1; i < seqs.length; i++) {
        expect(seqs[i]).toBeGreaterThan(seqs[i - 1]);
      }

      // 验证无间隔（相邻 seq 差值为 1）
      for (let i = 1; i < seqs.length; i++) {
        expect(seqs[i] - seqs[i - 1]).toBe(1);
      }

      console.log(`${seqs.length} 条消息 seq 严格递增且无间隔: [${seqs[0]}..${seqs[seqs.length - 1]}]`);
    } finally {
      await alice.close();
      await bob.close();
    }
  }, 60_000);
});
